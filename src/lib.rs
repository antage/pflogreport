//! Reading and analysis half of `pflogreport`: what a Postfix log line is, how the
//! lines of one delivery attempt are put back together, and what the remote server's
//! reply means.
//!
//! The binary (`src/main.rs`) owns everything else: command line, files and stdin,
//! and the three reports. Keeping the analysis here is what lets `benches/hot_path.rs`
//! measure it without running the tool.
//!
//! The two entry points are [`log_line::LogLine::parse`] for a single line and
//! [`message::Message::analyze`] for a whole delivery attempt, whose lines arrive in
//! any order and carry the reason for a failure in the words of a foreign mail server
//! ([`reason::parse_reason`]).

pub mod log_line;
pub mod message;
pub mod reason;
pub mod reason_stats;