use chrono::{
    NaiveDateTime,
    NaiveDate,
    NaiveTime, Datelike,
};
use nom::{
    branch::alt,
    bytes::complete::{
        is_a,
        tag,
        take,
        take_while,
        take_while_m_n,
        take_till1,
        take_until1,
    },
    error::{
        ContextError,
        ErrorKind,
        ParseError,
        VerboseError,
        VerboseErrorKind,
    },
    character::complete::{
        alpha1,
        alphanumeric1,
        not_line_ending,
        line_ending,
        multispace1,
        one_of,
    },
    combinator::{
        map,
        map_opt,
        opt,
        recognize,
    },
    multi::{
        many0_count,
    },
    sequence::{
        pair,
        preceded,
        terminated,
        tuple,
    }
};

// VerboseError is the only nom error type that carries context strings, so a
// rejected queue ID can name the reason instead of a bare ErrorKind.
type PResult<'a, O> = nom::IResult<&'a [u8], O, VerboseError<&'a [u8]>>;

fn parse_month(input: &[u8]) -> PResult<'_, u32> {
    map(
        alt((
            tag(b"Jan"),
            tag(b"Feb"),
            tag(b"Mar"),
            tag(b"Apr"),
            tag(b"May"),
            tag(b"Jun"),
            tag(b"Jul"),
            tag(b"Aug"),
            tag(b"Sep"),
            tag(b"Oct"),
            tag(b"Nov"),
            tag(b"Dec"),
        )),
        |month_str: &[u8]| {
            match month_str {
                b"Jan" => 1,
                b"Feb" => 2,
                b"Mar" => 3,
                b"Apr" => 4,
                b"May" => 5,
                b"Jun" => 6,
                b"Jul" => 7,
                b"Aug" => 8,
                b"Sep" => 9,
                b"Oct" => 10,
                b"Nov" => 11,
                b"Dec" => 12,
                _ => panic!("Unknown month")
            }
        }
    )(input)
}

fn parse_time(input: &[u8]) -> PResult<'_, NaiveTime> {
    map_opt(
        tuple((
            nom::character::complete::u8,
            tag(b":"),
            nom::character::complete::u8,
            tag(b":"),
            nom::character::complete::u8,
        )),
        |(hours, _, minutes, _, seconds)| {
            NaiveTime::from_hms_opt(hours as u32, minutes as u32, seconds as u32)
        }
    )(input)
}

fn parse_syslog_timestamp(input: &[u8]) -> PResult<'_, NaiveDateTime> {
    map_opt(
        tuple((
            parse_month,
            multispace1,
            nom::character::complete::u8,
            multispace1,
            parse_time,
        )),
        |(month, _, day, _, time)| {
            Some(
                NaiveDateTime::new(
                    NaiveDate::from_ymd_opt(
                        chrono::offset::Local::now().year(),
                        month,
                        day as u32
                    )?,
                    time
                )
            )
        }
    )(input)
}

// 2026-08-02T00:00:29(.365828)(+00:00|Z) — the year is taken from the log line.
fn parse_rfc3339_timestamp(input: &[u8]) -> PResult<'_, NaiveDateTime> {
    map_opt(
        tuple((
            nom::character::complete::u32,
            tag("-"),
            nom::character::complete::u32,
            tag("-"),
            nom::character::complete::u32,
            tag("T"),
            nom::character::complete::u8,
            tag(":"),
            nom::character::complete::u8,
            tag(":"),
            nom::character::complete::u8,
            opt(
                preceded(
                    tag("."),
                    take_while_m_n(1, 9, |c: u8| c.is_ascii_digit()),
                ),
            ),
            alt((
                tag("Z"),
                preceded(one_of("+"), take(5usize)),
            )),
        )),
        |(year, _, month, _, day, _, hour, _, minute, _, second, _, _)| {
            let year = i32::try_from(year).ok()?;
            NaiveDate::from_ymd_opt(year, month, day)
                .and_then(|date| date.and_hms_opt(hour as u32, minute as u32, second as u32))
        }
    )(input)
}

fn parse_timestamp(input: &[u8]) -> PResult<'_, NaiveDateTime> {
    alt((
        parse_rfc3339_timestamp,
        parse_syslog_timestamp,
    ))(input)
}

fn parse_hostname(input: &[u8]) -> PResult<'_, &[u8]> {
    recognize(
        pair(
            alpha1,
            many0_count(
                alt((
                    alphanumeric1,
                    is_a("-.")
                ))
            )
        )
    )(input)
}

fn parse_program_subsystem_pid(input: &[u8]) -> PResult<'_, (String, Option<String>, u64)> {
    map(
        tuple((
            take_till1(|c| c == b'/' || c == b'['),
            opt(
                preceded(
                    tag("/"),
                    take_until1("["),
                ),
            ),
            tag("["),
            nom::character::complete::u64,
            tag("]"),
        )),
        |(program, subsystem, _, pid, _)| {
            (
                String::from_utf8_lossy(program).into_owned(),
                subsystem.map(|s| String::from_utf8_lossy(s).into_owned()),
                pid,
            )
        }
    )(input)
}

// Postfix queue IDs are hex digits. The two MXes this tool is run against
// emit 10 and 12 digit ones (README "How it works"), and this range is a hard
// assumption, not a guess: nom does not backtrack, so eating at most
// QUEUE_ID_MAX_LEN of a longer run makes the ":" that follows the ID fail to
// match, the field is then treated as absent, and the line is kept WITHOUT a
// message ID - it silently drops out of the message it belongs to. A Postfix
// with the pre-3.6 7 digit IDs would report not a single message and not a
// single error. A hex run followed by ":" outside this range is therefore a
// parse error. Widen both bounds together if a wider Postfix shows up.
const QUEUE_ID_MIN_LEN: usize = 10;
const QUEUE_ID_MAX_LEN: usize = 12;

fn is_queue_id_char(c: u8) -> bool {
    char::from(c).is_ascii_hexdigit()
}

fn queue_id_error<'a>(input: &'a [u8], reason: &'static str) -> nom::Err<VerboseError<&'a [u8]>> {
    // Failure, not Error: no backtrack around this point is wanted, the
    // caller must see it.
    nom::Err::Failure(ContextError::add_context(
        input,
        reason,
        VerboseError::from_error_kind(input, ErrorKind::Verify),
    ))
}

// The optional " <queue ID>:" field between the program stamp and the text.
// Returns None, leaving input untouched, when the line carries no queue ID.
fn parse_message_id(input: &[u8]) -> PResult<'_, Option<u64>> {
    let Ok((after_ws, _)) = multispace1::<&[u8], VerboseError<&[u8]>>(input) else {
        return Ok((input, None));
    };
    let (after_run, run) = take_while(is_queue_id_char)(after_ws)?;
    let Ok((after_colon, _)) = tag::<&[u8], &[u8], VerboseError<&[u8]>>(b":")(after_run) else {
        // Not an ID field at all: "connect from host[192.0.2.1]", "uid=1000 ..".
        return Ok((input, None));
    };
    if run.is_empty() {
        return Ok((input, None));
    }
    if run.len() < QUEUE_ID_MIN_LEN || run.len() > QUEUE_ID_MAX_LEN {
        return Err(queue_id_error(after_ws, "queue ID must be 10-12 hex digits"));
    }
    let Some(id) = std::str::from_utf8(run)
        .ok()
        .and_then(|id_str| u64::from_str_radix(id_str, 16).ok())
    else {
        return Err(queue_id_error(after_ws, "queue ID is not a hex number"));
    };
    Ok((after_colon, Some(id)))
}

#[derive(Debug)]
pub struct LogLine {
    // Parsed as part of the line grammar; not consumed by analysis yet.
    #[allow(dead_code)]
    pub timestamp: NaiveDateTime,
    #[allow(dead_code)]
    pub hostname: String,
    pub program: String,
    pub subsystem: Option<String>,
    #[allow(dead_code)]
    pub pid: u64,
    pub message_id: Option<u64>,
    pub content: String,
}

impl LogLine {
    pub fn parse(input: &[u8]) -> PResult<'_, LogLine> {
        map_opt(
            terminated(
                tuple((
                    parse_timestamp,
                    multispace1,
                    parse_hostname,
                    multispace1,
                    parse_program_subsystem_pid,
                    tag(":"),
                    parse_message_id,
                    multispace1,
                    not_line_ending,
                )),
                opt(line_ending),
            ),
            |(timestamp, _, hostname, _, prog_subsystem_pid, _, message_id, _, line)| {
                let log_line =
                    LogLine {
                        timestamp: timestamp,
                        hostname: String::from_utf8_lossy(hostname).into_owned(),
                        program: prog_subsystem_pid.0,
                        subsystem: prog_subsystem_pid.1,
                        pid: prog_subsystem_pid.2,
                        message_id,
                        content: String::from_utf8_lossy(line).into_owned(),
                    };
                Some(log_line)
            }
        )(input)
    }
}

// A one-line description of a parse failure: the context strings the parser
// attached (see queue_id_error), or the bare nom error when it attached none.
// Debug on a VerboseError<&[u8]> prints every input slice as byte numbers,
// which buries the reason.
pub fn parse_error_text(err: &nom::Err<VerboseError<&[u8]>>) -> String {
    let inner: &VerboseError<&[u8]> = match err {
        nom::Err::Error(inner) | nom::Err::Failure(inner) => inner,
        _ => return "unexpected end of input".to_string(),
    };
    let mut contexts: Vec<&str> = inner
        .errors
        .iter()
        .filter_map(|(_, kind)| match kind {
            VerboseErrorKind::Context(ctx) => Some(*ctx),
            _ => None,
        })
        .collect();
    if contexts.is_empty() {
        // No context attached: name the position the parser gave up at, since
        // Debug on this error type dumps every input slice as byte numbers.
        let Some((at, kind)) = inner.errors.first() else {
            return "unexpected end of input".to_string();
        };
        let (head, _) = at.split_at(at.len().min(40));
        return format!("unexpected text at \"{}\" ({kind:?})", String::from_utf8_lossy(head));
    }
    contexts.dedup();
    contexts.join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, Timelike};

    #[test]
    fn parse_line_with_message_id() {
        let input =
            b"Dec 17 00:03:01 s1 postfix/qmgr[1859961]: A1B2C3D4E5: from=<sender@example.com>, size=1234, nrcpt=1 (queue active)\n";
        let (_, line) = LogLine::parse(input).unwrap();
        assert_eq!(line.timestamp.month(), 12);
        assert_eq!(line.timestamp.day(), 17);
        assert_eq!(line.timestamp.hour(), 0);
        assert_eq!(line.timestamp.minute(), 3);
        assert_eq!(line.timestamp.second(), 1);
        assert_eq!(line.hostname, "s1");
        assert_eq!(line.program, "postfix");
        assert_eq!(line.subsystem, Some("qmgr".to_string()));
        assert_eq!(line.pid, 1859961);
        assert_eq!(line.message_id, Some(0xA1B2C3D4E5));
        assert_eq!(
            line.content,
            "from=<sender@example.com>, size=1234, nrcpt=1 (queue active)"
        );
    }

    #[test]
    fn parse_line_without_message_id() {
        let input = b"Dec 17 00:02:44 s1 postfix/smtpd[1859960]: connect from host.example.com[192.0.2.240]";
        let (_, line) = LogLine::parse(input).unwrap();
        assert_eq!(line.program, "postfix");
        assert_eq!(line.subsystem, Some("smtpd".to_string()));
        assert_eq!(line.pid, 1859960);
        assert_eq!(line.message_id, None);
        assert_eq!(line.content, "connect from host.example.com[192.0.2.240]");
    }

    #[test]
    fn parse_line_with_twelve_digit_message_id() {
        let input = b"Dec 17 00:03:01 s1 postfix/smtp[123]: A1B2C3D4E5F6: to=<rcpt@example.com>";
        let (_, line) = LogLine::parse(input).unwrap();
        assert_eq!(line.message_id, Some(0xA1B2C3D4E5F6));
        assert_eq!(line.content, "to=<rcpt@example.com>");
    }

    #[test]
    fn parse_line_with_too_wide_message_id_fails() {
        let input = b"Dec 17 00:03:01 s1 postfix/smtp[123]: A1B2C3D4E5F67: to=<rcpt@example.com>";
        let err = format!("{:?}", LogLine::parse(input).unwrap_err());
        assert!(err.contains("queue ID must be 10-12 hex digits"), "{err}");
    }

    #[test]
    fn parse_line_with_too_narrow_message_id_fails() {
        let input = b"Dec 17 00:03:01 s1 postfix/cleanup[123]: A1B2C3D: message-id=<a@example.com>";
        let err = format!("{:?}", LogLine::parse(input).unwrap_err());
        assert!(err.contains("queue ID must be 10-12 hex digits"), "{err}");
    }

    #[test]
    fn parse_short_hex_word_in_text_is_not_a_message_id() {
        let input = b"Dec 17 00:03:01 s1 postfix/smtpd[123]: disconnect from abc[192.0.2.1]";
        let (_, line) = LogLine::parse(input).unwrap();
        assert_eq!(line.message_id, None);
        assert_eq!(line.content, "disconnect from abc[192.0.2.1]");
    }

    #[test]
    fn parse_line_with_single_digit_day() {
        let input = b"Jan  5 12:34:56 mail1 postfix/master[123]: daemon running";
        let (_, line) = LogLine::parse(input).unwrap();
        assert_eq!(line.timestamp.month(), 1);
        assert_eq!(line.timestamp.day(), 5);
        assert_eq!(line.hostname, "mail1");
        assert_eq!(line.subsystem, Some("master".to_string()));
        assert_eq!(line.content, "daemon running");
    }

    #[test]
    fn parse_line_without_subsystem() {
        let input = b"Dec 17 00:02:44 s1 rsyslogd[12345]: some random message";
        let (_, line) = LogLine::parse(input).unwrap();
        assert_eq!(line.program, "rsyslogd");
        assert_eq!(line.subsystem, None);
        assert_eq!(line.message_id, None);
        assert_eq!(line.content, "some random message");
    }

    #[test]
    fn parse_invalid_day_fails() {
        assert!(LogLine::parse(b"Dec 32 00:00:00 s1 postfix/smtp[1]: hello").is_err());
    }

    #[test]
    fn parse_invalid_time_fails() {
        assert!(LogLine::parse(b"Dec 17 25:00:00 s1 postfix/smtp[1]: hello").is_err());
    }

    #[test]
    fn parse_error_text_without_context_names_the_position() {
        let err = LogLine::parse(b"this is not a log line").unwrap_err();
        let text = parse_error_text(&err);
        assert!(text.starts_with("unexpected text at \"this is not a log line\""), "{text}");
        assert!(!text.contains("VerboseError"), "{text}");
    }

    #[test]
    fn parse_garbage_line_fails() {
        assert!(LogLine::parse(b"this is not a log line").is_err());
    }

    #[test]
    fn parse_rfc3339_line_with_fraction_and_offset() {
        let input = b"2026-08-02T00:00:29.365828+00:00 hc5 postfix/smtpd[3635194]: connect from host.example.com[192.0.2.240]";
        let (_, line) = LogLine::parse(input).unwrap();
        assert_eq!(line.timestamp.year(), 2026);
        assert_eq!(line.timestamp.month(), 8);
        assert_eq!(line.timestamp.day(), 2);
        assert_eq!(line.timestamp.hour(), 0);
        assert_eq!(line.timestamp.minute(), 0);
        assert_eq!(line.timestamp.second(), 29);
        assert_eq!(line.hostname, "hc5");
        assert_eq!(line.program, "postfix");
        assert_eq!(line.subsystem, Some("smtpd".to_string()));
        assert_eq!(line.pid, 3635194);
        assert_eq!(line.message_id, None);
        assert_eq!(line.content, "connect from host.example.com[192.0.2.240]");
    }

    #[test]
    fn parse_rfc3339_line_with_z_and_message_id() {
        let input = b"2026-08-02T01:03:05Z mail1 postfix/qmgr[1]: A1B2C3D4E5F6: from=<a@b.c>, size=1, nrcpt=1 (queue active)";
        let (_, line) = LogLine::parse(input).unwrap();
        assert_eq!(line.timestamp.year(), 2026);
        assert_eq!(line.timestamp.minute(), 3);
        assert_eq!(line.message_id, Some(0xA1B2C3D4E5F6));
        assert_eq!(line.content, "from=<a@b.c>, size=1, nrcpt=1 (queue active)");
    }

    #[test]
    fn parse_rfc3339_invalid_date_fails() {
        assert!(LogLine::parse(b"2026-02-30T00:00:00+00:00 s1 postfix/smtp[1]: hello").is_err());
    }
}
