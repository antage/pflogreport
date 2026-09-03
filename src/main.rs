use std::collections::BTreeMap;
use std::default::Default;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand, Args};
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
    #[arg(value_name = "LOG_FILE")]
    log_file: PathBuf,

    /// Output format: json (default: console)
    #[arg(short = 'f', long)]
    format: Option<String>,
}

#[derive(Args)]
struct BouncedArgs {
    #[arg(value_name = "LOG_FILE")]
    log_file: PathBuf,

    #[arg(short = 'v', long)]
    verbose: bool,
    /// Output format: json (default: console)
    #[arg(short = 'f', long)]
    format: Option<String>,
    /// Group reasons by: addr, domain (default: no grouping)
    #[arg(short = 'g', long)]
    group_by: Option<String>
}

#[derive(Args)]
struct DeferredArgs {
    #[arg(value_name = "LOG_FILE")]
    log_file: PathBuf,

    #[arg(short = 'v', long)]
    verbose: bool,
    /// Output format: json (default: console)
    #[arg(short = 'f', long)]
    format: Option<String>,
    /// Group reasons by: addr, domain (default: no grouping)
    #[arg(short = 'g', long)]
    group_by: Option<String>
}

const LINE_CHUNK_SIZE: usize = 100_000;

fn load_messages(log_file: &Path) -> Result<BTreeMap<u64, Message>> {
    let mut logs_by_message_id = BTreeMap::<u64, Message>::new();

    let file = File::open(log_file)?;
    let buf = BufReader::new(file);
    let mut lines = buf.lines();

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
                .map_err(|err| anyhow!("Can't parse log file: {:?}. At line: \"{}\"", err, line_str))?
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
            let logs_by_message_id = load_messages(&args.log_file)?;
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
            let logs_by_message_id = load_messages(&args.log_file)?;
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
            let logs_by_message_id = load_messages(&args.log_file)?;
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
