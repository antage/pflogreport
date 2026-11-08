//! Tests of what a user actually runs: the binary, its options, its exit codes and the
//! output the README documents. The unit tests in `src/` hand pieces of a log to one
//! function; these hand a whole file to the program.
//!
//! They run over `tests/fixtures/deliveries.log`, a log small enough to count by hand,
//! whose contents are written out below. Read that list before trusting an expected
//! string: an expectation here should be provable from the fixture, not copied from
//! whatever the program printed.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

/// The log these tests run over. An integration test runs with the package root as its
/// working directory, so a relative path would do; spelling it out makes a failing test
/// print a path that can be pasted into a shell.
fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// Six deliveries and two lines that belong to no delivery:
///
/// - still in the queue: one with only `qmgr` and `cleanup` lines, which counts as
///   `Unknown`;
/// - sent: one;
/// - bounced: two `NoSuchUser` (`bob@example.com` and `Bob@EXAMPLE.com`) and one `Other`
///   (`Ted@Mail.EXAMPLE.com`, a reply no pattern knows, on an RFC 3339 timestamp);
/// - deferred: `ConnectionTimedOut` and `OverQuotaTemp`, both to `carol@example.net`;
/// - a `postfix/master` line and an `rsyslogd` line, which are not deliveries: the counts
///   below add up to seven messages, so the tests fail if either ever starts counting.
///
/// The numbers follow from that: 1 unknown, 1 sent, 2 deferred, 3 bounced. The domain of
/// an address is folded to lowercase and the mailbox part is left as written, which is
/// what the grouping tests are really about.
const DELIVERIES: &str = "deliveries.log";

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pflogreport"))
        .args(args)
        .output()
        .expect("the binary built for this test has to start")
}

/// Run the tool over the fixture with these arguments.
fn on_fixture(args: &[&str]) -> Output {
    let log = fixture(DELIVERIES);
    let mut full: Vec<&str> = args.to_vec();
    full.push(log.to_str().expect("the fixture path is UTF-8"));
    run(&full)
}

/// Run the tool and compare its standard output with what the README promises.
#[track_caller]
fn assert_stdout(args: &[&str], expected: &str) {
    let out = on_fixture(args);
    assert!(
        out.status.success(),
        "`pflogreport {}` exited with {}: {}",
        args.join(" "),
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr),
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        expected,
        "`pflogreport {}` printed something else",
        args.join(" "),
    );
}

#[test]
fn stats_counts_every_final_status() {
    assert_stdout(
        &["stats"],
        "Stats:\n\
         \tUnknown = 1\n\
         \tSent = 1\n\
         \tDeferred = 2\n\
         \tBounced = 3\n",
    );
    assert_stdout(
        &["stats", "-f", "json"],
        "{\"unknown\":1,\"sent\":1,\"deferred\":2,\"bounced\":3}\n",
    );
}

#[test]
fn bounced_counts_the_reason_kinds_of_failed_deliveries() {
    assert_stdout(
        &["bounced"],
        "All reasons:\n\
         \t         2 NoSuchUser\n\
         \t         1 Other\n",
    );
    assert_stdout(&["bounced", "-f", "json"], "{\"NoSuchUser\":2,\"Other\":1}\n");
}

/// Grouping is where the shape of an address changes the report, so both keys are pinned:
/// `Bob@EXAMPLE.com` and `bob@example.com` are one domain but two mailboxes, because
/// Postfix without folding in `virtual_alias_maps` delivers them to different mailboxes.
#[test]
fn grouping_folds_the_domain_but_not_the_mailbox() {
    assert_stdout(
        &["bounced", "-g", "domain"],
        "Reasons by TO domain:\n\
         \texample.com:\n\
         \t\t         2 NoSuchUser\n\
         \tmail.example.com:\n\
         \t\t         1 Other\n",
    );
    assert_stdout(
        &["bounced", "-g", "domain", "-f", "json"],
        "{\"example.com\":{\"NoSuchUser\":2},\"mail.example.com\":{\"Other\":1}}\n",
    );
    assert_stdout(
        &["bounced", "-g", "addr", "-f", "json"],
        concat!(
            "{\"Bob@example.com\":{\"NoSuchUser\":1},",
            "\"Ted@mail.example.com\":{\"Other\":1},",
            "\"bob@example.com\":{\"NoSuchUser\":1}}\n",
        ),
    );
}

/// A verbose reason carries the remote host and IP and is no longer usable as an object
/// key, so the JSON becomes an array of `[reason, count]` pairs.
#[test]
fn verbose_json_reports_the_full_reason_with_its_count() {
    assert_stdout(
        &["bounced", "-v", "-f", "json"],
        concat!(
            "[[{\"hostname\":\"mx.example.org\",\"ipaddr\":\"198.51.100.7\",",
            "\"kind\":\"NoSuchUser\"},2],",
            "[{\"kind\":\"Other\",\"message\":\"host mx.example.org[198.51.100.7] said: ",
            "550 5.0.0 Unrecognised reply from the remote host, code 999 ",
            "(in reply to RCPT TO command)\"},1]]\n",
        ),
    );
}

#[test]
fn deferred_counts_the_reasons_of_retried_deliveries() {
    assert_stdout(
        &["deferred"],
        "All reasons:\n\
         \t         1 ConnectionTimedOut\n\
         \t         1 OverQuotaTemp\n",
    );
    assert_stdout(
        &["deferred", "-f", "json"],
        "{\"ConnectionTimedOut\":1,\"OverQuotaTemp\":1}\n",
    );
    assert_stdout(
        &["deferred", "-g", "addr", "-f", "json"],
        "{\"carol@example.net\":{\"ConnectionTimedOut\":1,\"OverQuotaTemp\":1}}\n",
    );
}

/// Every option the README documents, accepted by the commands it documents it for. The
/// point is that the documented surface exists: a dropped flag or a renamed value fails
/// here, where it would otherwise fail in someone's shell.
#[test]
fn the_documented_options_are_accepted_by_the_documented_commands() {
    for args in [
        vec!["stats"],
        vec!["stats", "-f", "json"],
        vec!["stats", "-y", "2019"],
        vec!["bounced"],
        vec!["bounced", "-f", "json"],
        vec!["bounced", "-g", "addr"],
        vec!["bounced", "-g", "domain", "-f", "json"],
        vec!["bounced", "-v"],
        vec!["bounced", "-v", "-g", "addr", "-f", "json", "-y", "2019"],
        vec!["deferred"],
        vec!["deferred", "-f", "json"],
        vec!["deferred", "-g", "addr"],
        vec!["deferred", "-g", "domain", "-f", "json"],
        vec!["deferred", "-v"],
        vec!["deferred", "-v", "-g", "addr", "-f", "json", "-y", "2019"],
    ] {
        let out = on_fixture(&args);
        assert!(
            out.status.success() && !out.stdout.is_empty(),
            "`pflogreport {}` should work, but exited with {}: {}",
            args.join(" "),
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr),
        );
    }
}

#[test]
fn reading_stdin_gives_the_same_report_as_reading_a_file() {
    let content = std::fs::read(fixture(DELIVERIES)).expect("the fixture has to be there");
    for args in [
        vec!["stats"],
        vec!["bounced", "-f", "json"],
        vec!["deferred", "-g", "addr", "-f", "json"],
    ] {
        let from_file = on_fixture(&args);
        let mut pipe_args = args.clone();
        pipe_args.push("-");
        let mut child = Command::new(env!("CARGO_BIN_EXE_pflogreport"))
            .args(&pipe_args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the binary has to start");
        // The write end has to be closed for the tool to see the end of the log, so the
        // handle is taken and dropped rather than borrowed.
        {
            let mut log_in = child.stdin.take().expect("a piped stdin");
            log_in.write_all(&content).expect("writing the log to stdin");
        }
        let from_pipe = child.wait_with_output().expect("waiting for the binary");
        assert_eq!(
            from_pipe.stdout, from_file.stdout,
            "`{}` differs between a file and stdin: {}",
            args.join(" "),
            String::from_utf8_lossy(&from_pipe.stderr),
        );
    }
}

#[test]
fn a_file_that_is_not_there_fails_with_the_os_message() {
    let out = run(&["stats", "/this/file/is/not/here"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "Error: No such file or directory (os error 2)\n",
    );
}

#[test]
fn a_line_that_is_not_a_log_line_names_itself() {
    let out = run(&["stats", fixture("broken.log").to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    let message = String::from_utf8_lossy(&out.stderr);
    assert!(
        message.contains("Can't parse log file"),
        "the error should say what failed: {message}",
    );
    assert!(
        message.contains("At line: \"this is not a log line\""),
        "the error should quote the line that failed: {message}",
    );
}

/// The README lists the values an option takes; the parser refuses anything else before
/// the log is opened, naming the values that are allowed.
#[test]
fn unknown_option_values_are_refused_with_the_allowed_ones() {
    let log = fixture(DELIVERIES);
    let log = log.to_str().unwrap();
    for (command, flag, value, allowed) in [
        ("stats", "-f", "yaml", "[possible values: json]"),
        ("bounced", "-g", "recipient", "[possible values: addr, domain]"),
        ("stats", "-y", "99999", "99999 is not in 1000..=9999"),
    ] {
        let out = run(&[command, flag, value, log]);
        let message = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(2),
            "`{command} {flag} {value}` should be refused: {message}",
        );
        assert!(
            message.contains(&format!("invalid value '{value}'")),
            "the error should name the value: {message}",
        );
        assert!(
            message.contains(allowed),
            "the error should list what is allowed: {message}",
        );
    }
}

#[test]
fn version_and_help_exit_zero() {
    let out = run(&["--version"]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("pflogreport "));
    let out = run(&["--help"]);
    assert!(out.status.success());
    let help = String::from_utf8_lossy(&out.stdout);
    for command in ["stats", "bounced", "deferred"] {
        assert!(help.contains(command), "the help should list `{command}`: {help}");
    }
}