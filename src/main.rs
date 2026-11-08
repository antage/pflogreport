use std::collections::BTreeMap;
use std::default::Default;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, stdin};
use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use chrono::{DateTime, Datelike, Local};
use clap::{Parser, Subcommand, Args};
use encoding_rs::UTF_8;
use encoding_rs_io::DecodeReaderBytesBuilder;
use mimalloc::MiMalloc;
use rayon::prelude::*;

// A line of Postfix log costs two or three heap Strings and they are allocated on rayon
// threads over inputs of several gigabytes, which the system allocator served largely in
// the kernel: on a 2.26 GB log mimalloc measured -25% wall time (8.3 s to 6.3 s, faster in
// 18 of 18 paired runs, system time 13.5 s to 9.2 s). See CHANGELOG for what it costs.
#[global_allocator]
static ALLOCATOR: MiMalloc = MiMalloc;

// Reading and analysis live in the library half of this package (src/lib.rs), so that
// benches/hot_path.rs can measure them; this binary owns the command line, the input
// and the three reports.
use pflogreport::log_line;
use pflogreport::log_line::{LogLine, LogStamp, YearTracker};
use pflogreport::message::Message;
use pflogreport::reason::{Reason, ReasonKind};
use pflogreport::reason_stats::ReasonStats;

mod cmd_stats;
mod cmd_bounced;
mod cmd_deferred;

// A plausible four-digit year: anything outside it is a typo, and chrono could not
// place a log date in it anyway.
const YEAR_RANGE: RangeInclusive<i64> = 1000..=9999;

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

    /// Assume this year for timestamps that do not state one (default: the year
    /// of the log file)
    #[arg(short = 'y', long, value_name = "YEAR",
          value_parser = clap::value_parser!(i32).range(YEAR_RANGE))]
    year: Option<i32>,

    /// Output format: json (default: console)
    #[arg(short = 'f', long, value_parser = ["json"])]
    format: Option<String>,
}

#[derive(Args)]
struct BouncedArgs {
    /// Log file to analyze, or "-" to read stdin
    #[arg(value_name = "LOG_FILE")]
    log_file: PathBuf,

    /// Assume this year for timestamps that do not state one (default: the year
    /// of the log file)
    #[arg(short = 'y', long, value_name = "YEAR",
          value_parser = clap::value_parser!(i32).range(YEAR_RANGE))]
    year: Option<i32>,

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

    /// Assume this year for timestamps that do not state one (default: the year
    /// of the log file)
    #[arg(short = 'y', long, value_name = "YEAR",
          value_parser = clap::value_parser!(i32).range(YEAR_RANGE))]
    year: Option<i32>,

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

// The year the first line of a log belongs to. Classic syslog stamps do not state
// it and YearTracker can only count rollovers from here, so the anchor comes
// from the outside: --year, else the year the file itself was last written (a
// rotated log read after midnight is still last year's), else the clock, which
// is all a stream on stdin offers.
fn base_year(log_file: &Path, stated: Option<i32>) -> i32 {
    stated.unwrap_or_else(|| match log_file.metadata().and_then(|m| m.modified()) {
        Ok(written) => DateTime::<Local>::from(written).year(),
        Err(_) => Local::now().year(),
    })
}

fn load_messages(input: LogInput, base_year: i32) -> Result<BTreeMap<u64, Message>> {
    let mut logs_by_message_id = BTreeMap::<u64, Message>::new();
    let mut years = YearTracker::new(base_year);

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
            let mut log_line = result
                .map_err(|err| anyhow!("Can't parse log file \"{}\": {}. At line: \"{}\"", name, log_line::parse_error_text(&err), line_str))?
                .1;
            // The merge walk is already sequential and in file order, which is
            // exactly what resolving a year-less stamp needs; resolving here
            // costs no extra pass over the lines.
            let resolved = years.resolve(log_line.stamp)
                .ok_or_else(|| anyhow!("Can't parse log file \"{}\": no year holds this date. At line: \"{}\"", name, line_str))?;
            log_line.stamp = LogStamp::Absolute(resolved);
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
            let base = base_year(&args.log_file, args.year);
            let logs_by_message_id = load_messages(open_log(&args.log_file)?, base)?;
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
            let base = base_year(&args.log_file, args.year);
            let logs_by_message_id = load_messages(open_log(&args.log_file)?, base)?;
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
            let base = base_year(&args.log_file, args.year);
            let logs_by_message_id = load_messages(open_log(&args.log_file)?, base)?;
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
    // Which documented values the options accept is a question about the tool, so it is
    // answered in `tests/cli.rs`, over the binary. What stays here is the parser refusing
    // a value it was not given, which is cheaper to point at directly.
    use super::*;

    fn parse(cmd: &str, flag: &str, value: &str) -> clap::error::Result<Cli> {
        Cli::try_parse_from(["pflogreport", cmd, "-", flag, value])
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
