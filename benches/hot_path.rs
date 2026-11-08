//! The hot path of `pflogreport`, measured a function at a time: reading one log
//! line, working out what a remote server's reply means, and putting the lines of one
//! delivery attempt together.
//!
//! Run with `cargo bench`. Everything works on `fixtures/sample.log`, a synthetic log
//! of 94 deliveries whose outcome mix is that of a working mail server (most sent,
//! some deferred, few bounced), so the numbers are a real workload and not a best
//! case. It is 672 lines and 80 KB: small enough to live in the repository, big enough
//! for one pass to be measurable, and it contains no address that exists.
//!
//! Every bench times a whole pass over the fixture, so a per-line or per-message
//! figure is the printed time divided by 672 lines or 94 messages.

use divan::Bencher;
use pflogreport::log_line::LogLine;
use pflogreport::message::Message;
use pflogreport::reason::parse_reason;

const FIXTURE: &str = include_str!("fixtures/sample.log");

/// What the fixture holds: 672 lines of 94 deliveries. These are the divisors for a
/// per-line or per-delivery figure, and they are asserted inside every bench, so an
/// edited fixture cannot quietly turn a bench into a measurement of nothing.
const FIXTURE_LINES: usize = 672;
const FIXTURE_DELIVERIES: usize = 94;

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

/// What a reply means. The patterns are grouped by the command the reply answers, and
/// the biggest group - the one a `RCPT TO` reply is tried against - is some 80 regular
/// expressions long, so a reply that means nothing to the tool costs all of them. In
/// this fixture most lines are successes, and `250 Ok` means nothing to the tool.
#[divan::bench]
fn classify_reason(bencher: Bencher) {
    let reasons = reasons();
    assert_eq!(reasons.len(), FIXTURE_DELIVERIES,
        "every delivery should contribute one reason to classify");
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