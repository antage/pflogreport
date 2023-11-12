use std::collections::BTreeMap;
use std::default::Default;
use std::fs::File;
use std::io::{BufRead, BufReader};

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand, Args};

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
    #[arg(short = 'f', long)]
    format: Option<String>,
}

#[derive(Args)]
struct BouncedArgs {
    #[arg(short = 'v', long)]
    verbose: bool,
    #[arg(short = 'f', long)]
    format: Option<String>,
    #[arg(short = 'g', long)]
    group_by: Option<String>
}

#[derive(Args)]
struct DeferredArgs {
    #[arg(short = 'v', long)]
    verbose: bool,
    #[arg(short = 'f', long)]
    format: Option<String>,
    #[arg(short = 'g', long)]
    group_by: Option<String>
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut logs_by_message_id = BTreeMap::<u64, Message>::new();

    let log_file = File::open("data/mail.log")?;
    let buf = BufReader::new(log_file);
    for line in buf.lines() {
        let line_str = line?;
        let (_, log_line) =
            LogLine::parse(line_str.as_bytes())
                .map_err(|err| anyhow!("Can't parse log file: {:?}. At line: \"{}\"", err, line_str))?;
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

    for (_, msg) in logs_by_message_id.iter_mut() {
        msg.analyze()?;
    }

    match cli.command {
        Commands::Stats(args) => {
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
