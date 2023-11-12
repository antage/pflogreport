use chrono::{
    NaiveDateTime,
    NaiveDate,
    NaiveTime, Datelike,
};
use nom::{
    IResult,
    branch::alt,
    bytes::complete::{
        is_a,
        tag,
        take_while_m_n,
        take_till1,
        take_until1,
    },
    character::complete::{
        alpha1,
        alphanumeric1,
        not_line_ending,
        line_ending,
        multispace1,
    },
    combinator::{
        map,
        map_opt,
        map_res,
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

fn parse_month(input: &[u8]) -> IResult<&[u8], u32> {
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

fn parse_time(input: &[u8]) -> IResult<&[u8], NaiveTime> {
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

fn parse_timestamp(input: &[u8]) -> IResult<&[u8], NaiveDateTime> {
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

fn parse_hostname(input: &[u8]) -> IResult<&[u8], &[u8]> {
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

fn parse_program_subsystem_pid(input: &[u8]) -> IResult<&[u8], (String, Option<String>, u64)> {
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

fn parse_message_id(input: &[u8]) -> IResult<&[u8], u64> {
    map_res(
        take_while_m_n(
            10, 10,
            |c| {
                char::from(c).is_ascii_hexdigit()
            }
        ),
        |id| -> Result<u64, anyhow::Error> {
            let id_str = std::str::from_utf8(id)?;
            Ok(
                u64::from_str_radix(id_str, 16)?
            )
        }
    )(input)
}

pub struct LogLine {
    pub timestamp: NaiveDateTime,
    pub hostname: String,
    pub program: String,
    pub subsystem: Option<String>,
    pub pid: u64,
    pub message_id: Option<u64>,
    pub content: String,
}

impl LogLine {
    pub fn parse(input: &[u8]) -> IResult<&[u8], LogLine> {
        map_opt(
            terminated(
                tuple((
                    parse_timestamp,
                    multispace1,
                    parse_hostname,
                    multispace1,
                    parse_program_subsystem_pid,
                    tag(":"),
                    opt(
                        tuple((
                            multispace1,
                            parse_message_id,
                            tag(":"),
                        )),
                    ),
                    multispace1,
                    not_line_ending,
                )),
                opt(line_ending),
            ),
            |(timestamp, _, hostname, _, prog_subsystem_pid, _, message_id, _, line)| {
                let opt_message_id =
                    match message_id {
                        Some((_, id, _)) => Some(id),
                        None => None,
                    };
                let log_line =
                    LogLine {
                        timestamp: timestamp,
                        hostname: String::from_utf8_lossy(hostname).into_owned(),
                        program: prog_subsystem_pid.0,
                        subsystem: prog_subsystem_pid.1,
                        pid: prog_subsystem_pid.2,
                        message_id: opt_message_id,
                        content: String::from_utf8_lossy(line).into_owned(),
                    };
                Some(log_line)
            }
        )(input)
    }
}
