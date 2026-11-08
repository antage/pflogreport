//! The hot path of `pflogreport`, measured a function at a time: reading one log
//! line, working out what a remote server's reply means, and putting the lines of one
//! delivery attempt together.
//!
//! Run with `cargo bench`. Everything works on `fixtures/sample.log`, a synthetic log
//! of 94 deliveries (686 lines) that succeeds 40 times, defers 26 and bounces 28, and
//! holds a reply of each kind a pattern is kept for. It holds no address that exists.
//!
//! Every bench times a whole pass over the fixture, so a per-line or per-message
//! figure is the printed time divided by 686 lines or 94 messages.

use std::collections::BTreeMap;

use divan::Bencher;
use pflogreport::log_line::LogLine;
use pflogreport::message::Message;
use pflogreport::reason::{
    ReasonKind,
    ReasonType,
    parse_reason,
};

const FIXTURE: &str = include_str!("fixtures/sample.log");

/// What the fixture holds: 686 lines of 94 deliveries. These are the divisors for a
/// per-line or per-delivery figure, and they are asserted inside every bench, so an
/// edited fixture cannot quietly turn a bench into a measurement of nothing.
const FIXTURE_LINES: usize = 686;
const FIXTURE_DELIVERIES: usize = 94;

/// How many replies of the fixture land in each reason category. 48 are words no pattern
/// knows: 40 successes and 8 replies of a remote server that mean nothing to the tool, the
/// latter the ones that walk a whole group of patterns. 18 more are the local server's own
/// words about connections, DNS and the domain it tried to reach, and those are the
/// patterns that carry capture groups. The rest are replies of a remote server, two of them
/// answering `MAIL FROM`.
///
/// A reply whose text stops matching its pattern falls into `Other` and breaks this table,
/// so the bench fails instead of quietly measuring less than it claims to: 90 of the old
/// fixture's 94 replies were `Other` by accident, and it saw none of the work that
/// attributes a known reply.
const REASON_MIX: [(ReasonKind, usize); 13] = [
    (ReasonKind::AccessDenied, 4),
    (ReasonKind::BadMX, 2),
    (ReasonKind::BlockList, 2),
    (ReasonKind::ConnectionRefused, 3),
    (ReasonKind::ConnectionTimedOut, 5),
    (ReasonKind::DNSError, 3),
    (ReasonKind::LostConnection, 3),
    (ReasonKind::NoSuchUser, 11),
    (ReasonKind::Other, 48),
    (ReasonKind::OverQuotaPerm, 4),
    (ReasonKind::OverQuotaTemp, 4),
    (ReasonKind::RelayAccessDenied, 3),
    (ReasonKind::UnsolicitedMessageError, 2),
];

/// Lines of the fixture, as the reader would hand them to the parser.
fn lines() -> Vec<String> {
    FIXTURE.lines().map(str::to_string).collect()
}

/// Reason texts, taken out of the fixture rather than written out again here, so the
/// bench measures the words a server really says and not the ones this file invents.
/// The extraction mirrors `parse_status`: the text between the parentheses after
/// `status=<word>`, with the closing parenthesis dropped, which is what
/// `Message::analyze` hands to `parse_reason`.
fn reasons() -> Vec<String> {
    lines()
        .iter()
        .filter_map(|line| line.split_once("status="))
        .filter_map(|(_, status)| status.split_once(" ("))
        .map(|(_, parenthesized)| {
            parenthesized
                .strip_suffix(')')
                .unwrap_or(parenthesized)
                .to_string()
        })
        .collect()
}

/// Delivery attempts as `load_messages` hands them over: lines grouped by queue ID.
/// `Message::analyze` only reads them, so one set serves every repetition.
fn messages() -> Vec<Message> {
    let mut by_id: std::collections::BTreeMap<u64, Vec<LogLine>> =
        std::collections::BTreeMap::new();
    for line in lines() {
        let (_, parsed) = LogLine::parse(line.as_bytes())
            .unwrap_or_else(|_| panic!("the fixture has to parse: {line}"));
        if let Some(id) = parsed.message_id {
            by_id.entry(id).or_default().push(parsed);
        }
    }
    by_id
        .into_values()
        .map(|log_lines| Message {
            log_lines,
            ..Default::default()
        })
        .collect()
}

/// Reading one line: the grammar in `log_line`, nothing else. Everything in the input
/// goes through it.
#[divan::bench]
fn parse_line(bencher: Bencher) {
    let lines = lines();
    assert_eq!(lines.len(), FIXTURE_LINES, "the fixture is no longer what the benches divide by");
    bencher.bench_local(|| {
        let mut read = 0usize;
        for line in &lines {
            if LogLine::parse(line.as_bytes()).is_ok() {
                read += 1;
            }
        }
        divan::black_box(read)
    });
}

/// What a reply means. The patterns are grouped by the SMTP command the reply answers, so
/// a reply tries the patterns kept for its own command: some 84 for a `RCPT TO` reply, 23
/// for a `DATA` reply, 13 for the replies the local server makes itself, and 1 for a
/// `MAIL FROM` reply. A reply that means nothing to the tool pays for its whole group, and
/// 8 of the fixture's replies are `RCPT TO` or `DATA` replies of that kind.
#[divan::bench]
fn classify_reason(bencher: Bencher) {
    let reasons = reasons();
    assert_eq!(reasons.len(), FIXTURE_DELIVERIES,
        "every delivery should contribute one reason to classify");
    let mut counts: BTreeMap<ReasonKind, usize> = BTreeMap::new();
    for reason in &reasons {
        let kind = parse_reason(reason)
            .unwrap_or_else(|_| panic!("a reply of the fixture should parse: {reason}"))
            .kind();
        *counts.entry(kind).or_default() += 1;
    }
    let expected: BTreeMap<ReasonKind, usize> = REASON_MIX.into();
    assert_eq!(counts, expected,
        "the fixture no longer reaches the reason tables this bench is for");
    bencher.bench_local(|| {
        let mut classified = 0usize;
        for reason in &reasons {
            if parse_reason(reason).is_ok() {
                classified += 1;
            }
        }
        divan::black_box(classified)
    });
}

/// A whole delivery attempt: the fields of its lines read, the reason classified, the
/// status decided.
#[divan::bench]
fn analyze_message(bencher: Bencher) {
    let mut messages = messages();
    assert_eq!(messages.len(), FIXTURE_DELIVERIES,
        "the fixture is no longer what the benches divide by");
    bencher.bench_local(|| {
        let mut analyzed = 0usize;
        for message in &mut messages {
            if message.analyze().is_ok() {
                analyzed += 1;
            }
        }
        divan::black_box(analyzed)
    });
}

fn main() {
    divan::main();
}