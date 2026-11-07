use std::collections::BTreeMap;
use std::default::Default;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, stdin};
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand, Args};
use encoding_rs::UTF_8;
use encoding_rs_io::DecodeReaderBytesBuilder;
use rayon::prelude::*;

mod log_line;
use log_line::LogLine;

mod message;
use message::Message;

mod reason;
use reason::{Reason, ReasonKind};

mod reason_stats;
use reason_stats::ReasonStats;

mod cmd_stats;
mod cmd_bounced;
mod cmd_deferred;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Stats(StatsArgs),
    Bounced(BouncedArgs),
    Deferred(DeferredArgs),
}

#[derive(Args)]
struct StatsArgs {
    /// Log file to analyze, or "-" to read stdin
    #[arg(value_name = "LOG_FILE")]
    log_file: PathBuf,

    /// Output format: json (default: console)
    #[arg(short = 'f', long, value_parser = ["json"])]
    format: Option<String>,
}

#[derive(Args)]
struct BouncedArgs {
    /// Log file to analyze, or "-" to read stdin
    #[arg(value_name = "LOG_FILE")]
    log_file: PathBuf,

    #[arg(short = 'v', long)]
    verbose: bool,
    /// Output format: json (default: console)
    #[arg(short = 'f', long, value_parser = ["json"])]
    format: Option<String>,
    /// Group reasons by: addr, domain (default: no grouping)
    #[arg(short = 'g', long, value_parser = ["addr", "domain"])]
    group_by: Option<String>,
}

#[derive(Args)]
struct DeferredArgs {
    /// Log file to analyze, or "-" to read stdin
    #[arg(value_name = "LOG_FILE")]
    log_file: PathBuf,

    #[arg(short = 'v', long)]
    verbose: bool,
    /// Output format: json (default: console)
    #[arg(short = 'f', long, value_parser = ["json"])]
    format: Option<String>,
    /// Group reasons by: addr, domain (default: no grouping)
    #[arg(short = 'g', long, value_parser = ["addr", "domain"])]
    group_by: Option<String>,
}

// Lines per rayon task in load_messages: a chunk is read, parsed in parallel
// behind a barrier, then merged into the message map sequentially, so the
// size trades per-chunk sync overhead against a longer straggler tail and
// more resident memory. Measured on a 2.26 GB / 7.8 M line mail log, 32
// cores, warm cache, parse+merge median of 3: 10k 6032 ms, 50k 5417 ms,
// 100k 4795 ms, 250k 4816 ms, 1M 4647 ms. 100k is the knee: below it the
// barrier cost shows up (10k is 26% slower), above it 1M buys 3% for 400 MB
// more peak RSS (~460 B per buffered line). Re-measure if the merge stops
// being sequential.
const LINE_CHUNK_SIZE: usize = 100_000;

struct LogInput {
    name: String,
    reader: BufReader<Box<dyn Read>>,
}

// "-" means stdin, anything else is a file path.
fn open_log(path: &Path) -> Result<LogInput> {
    let (name, source): (String, Box<dyn Read>) = if path == Path::new("-") {
        ("<stdin>".to_string(), Box::new(stdin()))
    } else {
        (path.display().to_string(), Box::new(File::open(path)?))
    };

    // A mail log is bytes, not text: Postfix writes SMTP replies as they come
    // in, so a reply in another encoding (a Chinese MX answering in GBK, for
    // example) makes the whole stream invalid UTF-8, and one such line aborts
    // the log. Decode it as UTF-8 with invalid sequences replaced by the
    // replacement character. UTF_8 is spelled out on purpose: without an
    // explicit encoding the decoder only kicks in on a BOM and passes the
    // bytes through unchanged otherwise.
    Ok(LogInput {
        name,
        reader: BufReader::new(Box::new(
            DecodeReaderBytesBuilder::new()
                .encoding(Some(UTF_8))
                .build(source),
        )),
    })
}

fn load_messages(input: LogInput) -> Result<BTreeMap<u64, Message>> {
    let mut logs_by_message_id = BTreeMap::<u64, Message>::new();

    let LogInput { name, reader } = input;
    let mut lines = reader.lines();

    loop {
        let chunk: Vec<String> = lines
            .by_ref()
            .take(LINE_CHUNK_SIZE)
            .collect::<std::io::Result<Vec<String>>>()?;
        if chunk.is_empty() {
            break;
        }

        let parsed: Vec<_> = chunk
            .par_iter()
            .map(|line_str| LogLine::parse(line_str.as_bytes()))
            .collect();

        for (line_str, result) in chunk.iter().zip(parsed) {
            let log_line = result
                .map_err(|err| anyhow!("Can't parse log file \"{}\": {}. At line: \"{}\"", name, log_line::parse_error_text(&err), line_str))?
                .1;
            if let Some(message_id) = log_line.message_id {
                if let Some(entry) = logs_by_message_id.get_mut(&message_id) {
                    entry.log_lines.push(log_line);
                } else {
                    let msg = Message {
                        log_lines: vec![log_line],
                        ..Default::default()
                    };
                    logs_by_message_id.insert(message_id, msg);
                }
            }
        }

        if chunk.len() < LINE_CHUNK_SIZE {
            break;
        }
    }

    logs_by_message_id
        .par_iter_mut()
        .try_for_each(|(_, msg)| msg.analyze())?;

    Ok(logs_by_message_id)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Stats(args) => {
            let logs_by_message_id = load_messages(open_log(&args.log_file)?)?;
            let stats = cmd_stats::stats(&logs_by_message_id)?;
            match args.format {
                Some(fmt) => {
                    match fmt.as_ref() {
                        "json" => stats.print_json()?,
                        _ => stats.print_console()?,
                    }

                }
                _ => stats.print_console()?,
            }
        },
        Commands::Bounced(args) => {
            let logs_by_message_id = load_messages(open_log(&args.log_file)?)?;
            let bounced: Box<dyn ReasonStats> =
                if args.verbose {
                    Box::new(cmd_bounced::Bounced::<Reason>::new(&logs_by_message_id)?)
                } else {
                    Box::new(cmd_bounced::Bounced::<ReasonKind>::new(&logs_by_message_id)?)
                };
            match args.format {
                Some(fmt) => {
                    match fmt.as_ref() {
                        "json" => {
                            match args.group_by.as_deref() {
                                Some("addr") => {
                                    bounced.print_json_reasons_by_to_addr()?
                                },
                                Some("domain") => {
                                    bounced.print_json_reasons_by_to_domain()?
                                },
                                _ => {
                                    bounced.print_json_reasons()?
                                },
                            }
                        },
                        _ => {
                            match args.group_by.as_deref() {
                                Some("addr") => {
                                    bounced.print_console_reasons_by_to_addr()?
                                },
                                Some("domain") => {
                                    bounced.print_console_reasons_by_to_domain()?
                                },
                                _ => {
                                    bounced.print_console_reasons()?
                                },
                            }
                        }
                    }

                }
                _ => {
                    match args.group_by.as_deref() {
                        Some("addr") => {
                            bounced.print_console_reasons_by_to_addr()?
                        },
                        Some("domain") => {
                            bounced.print_console_reasons_by_to_domain()?
                        },
                        _ => {
                            bounced.print_console_reasons()?
                        },
                    }
                }
            }
        },
        Commands::Deferred(args) => {
            let logs_by_message_id = load_messages(open_log(&args.log_file)?)?;
            let deferred: Box<dyn ReasonStats> =
                if args.verbose {
                    Box::new(cmd_deferred::Deferred::<Reason>::new(&logs_by_message_id)?)
                } else {
                    Box::new(cmd_deferred::Deferred::<ReasonKind>::new(&logs_by_message_id)?)
                };
            match args.format {
                Some(fmt) => {
                    match fmt.as_ref() {
                        "json" => {
                            match args.group_by.as_deref() {
                                Some("addr") => {
                                    deferred.print_json_reasons_by_to_addr()?
                                },
                                Some("domain") => {
                                    deferred.print_json_reasons_by_to_domain()?
                                },
                                _ => {
                                    deferred.print_json_reasons()?
                                },
                            }
                        },
                        _ => {
                            match args.group_by.as_deref() {
                                Some("addr") => {
                                    deferred.print_console_reasons_by_to_addr()?
                                },
                                Some("domain") => {
                                    deferred.print_console_reasons_by_to_domain()?
                                },
                                _ => {
                                    deferred.print_console_reasons()?
                                },
                            }
                        },
                    }

                }
                _ => {
                    match args.group_by.as_deref() {
                        Some("addr") => {
                            deferred.print_console_reasons_by_to_addr()?
                        },
                        Some("domain") => {
                            deferred.print_console_reasons_by_to_domain()?
                        },
                        _ => {
                            deferred.print_console_reasons()?
                        },
                    }
        }
            }
        },
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(cmd: &str, flag: &str, value: &str) -> clap::error::Result<Cli> {
        Cli::try_parse_from(["pflogreport", cmd, "-", flag, value])
    }

    #[test]
    fn options_accept_the_documented_values() {
        for (cmd, flag, value) in [
            ("stats", "-f", "json"),
            ("bounced", "-f", "json"),
            ("deferred", "-f", "json"),
            ("bounced", "-g", "addr"),
            ("bounced", "-g", "domain"),
            ("deferred", "-g", "addr"),
            ("deferred", "-g", "domain"),
        ] {
            assert!(
                parse(cmd, flag, value).is_ok(),
                "{cmd} {flag} {value} must parse"
            );
        }
    }

    #[test]
    fn options_reject_an_unknown_value() {
        for (cmd, flag, value) in [
            ("stats", "-f", "xml"),
            ("bounced", "-f", "xml"),
            ("deferred", "-f", "xml"),
            ("bounced", "-g", "wrong"),
            ("deferred", "-g", "wrong"),
        ] {
            match parse(cmd, flag, value) {
                Err(err) => assert_eq!(err.kind(), clap::error::ErrorKind::InvalidValue),
                Ok(_) => panic!("{cmd} {flag} {value} must be rejected"),
            }
        }
    }
}
