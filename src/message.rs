use std::default::Default;

use anyhow::{Result, anyhow};
use nom::{
    IResult,
    branch::alt,
    bytes::complete::{
        take_while,
        take_while1,
        take_until,
        take_until1,
        tag,
    },
    character::complete::{
        multispace1,
    },
    combinator::{
        map,
        rest,
        verify,
    },
    multi::{
        separated_list1,
    },
    sequence::{
        tuple,
    }
};

use crate::log_line::LogLine;
use crate::reason::{Reason, parse_reason};

#[derive(Debug, PartialEq)]
pub enum Status {
    Unknown,
    Sent {
        reason: Reason,
    },
    Deferred {
        reason: Reason,
    },
    Bounced {
        reason: Reason,
    },
}

pub struct Message {
    pub log_lines: Vec<LogLine>,
    pub is_in_queue: bool,
    pub message_id: Option<String>,
    pub client: Option<(String, String)>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub size: Option<u64>,
    pub status: Status,
}

impl Message {
    pub fn analyze(&mut self) -> Result<()> {
        // is_in_queue
        self.is_in_queue = self.log_lines.len() > 0;
        if self.is_in_queue {
            for line in &self.log_lines {
                if line.program == "postfix" {
                    match line.subsystem.as_ref().map(|s| s.as_ref()) {
                        Some("qmgr") => {
                            if line.content == "removed" {
                                self.is_in_queue = false;
                            } else {
                                let (_, fields) =
                                    parse_fields(&line.content)
                                        .map_err(|err| {
                                            anyhow!("postfix/qmgr fields parsing error: {}", err)
                                        })?;
                                for (name, value) in fields {
                                    match name.as_ref() {
                                        "from" => {
                                            let (_, email) =
                                                parse_email(&value)
                                                    .map_err(|err| {
                                                        anyhow!("postfix/qmgr from field parsing error: {}", err)
                                                    })?;
                                            self.from = Some(email);
                                        },
                                        "size" => {
                                            let (_, size) =
                                                parse_size(&value)
                                                    .map_err(|err| {
                                                        anyhow!("postfix/qmgr size field parsing error: {}", err)
                                                    })?;
                                            self.size = Some(size);
                                        },
                                        _ => {},
                                    }
                                }
                            }
                        },
                        Some("smtpd") => {
                            let (_, fields) =
                                parse_fields(&line.content)
                                    .map_err(|err| {
                                        anyhow!("postfix/smtpd fields parsing error: {}", err)
                                    })?;
                            for (name, value) in fields {
                                match name.as_ref() {
                                    "client" => {
                                        let (_, (hostname, ip_addr)) =
                                            parse_client(&value)
                                                .map_err(|err| {
                                                    anyhow!("postfix/smtpd client field parsing error: {}", err)
                                                })?;
                                        self.client = Some((hostname, ip_addr));
                                    },
                                    _ => {},
                                }
                            }
                        },
                        Some("cleanup") => {
                            let (_, fields) =
                                parse_fields(&line.content)
                                    .map_err(|err| {
                                        anyhow!("postfix/cleanup fields parsing error: {}", err)
                                    })?;
                            for (name, value) in fields {
                                match name.as_ref() {
                                    "message-id" => {
                                        let (_, message_id) =
                                            parse_email(&value)
                                                .map_err(|err| {
                                                    anyhow!("postfix/cleanup message-id field parsing error: {}", err)
                                                })?;
                                        self.message_id = Some(message_id);
                                    },
                                    _ => {},
                                }
                            }
                        },
                        Some("smtp") => {
                            if line.content.starts_with("to=") {
                                let (_, fields) =
                                    parse_fields(&line.content)
                                        .map_err(|err| {
                                            anyhow!("postfix/smtp fields parsing error: {}", err)
                                        })?;
                                for (name, value) in fields {
                                    match name.as_ref() {
                                        "to" => {
                                            let (_, email) =
                                                parse_email(&value)
                                                    .map_err(|err| {
                                                        anyhow!("postfix/smtp to field parsing error: {}", err)
                                                    })?;
                                            self.to = Some(email);
                                        },
                                        "status" => {
                                            let (_, (status, reason)) =
                                                parse_status(&value)
                                                    .map_err(|err| {
                                                        anyhow!("postfix/smtp status field parsing error: {}", err)
                                                    })?;
                                            match status.as_ref() {
                                                "sent" => {
                                                    self.status = Status::Sent {
                                                        reason: parse_reason(&reason)?
                                                    };
                                                },
                                                "deferred" => {
                                                    self.status = Status::Deferred {
                                                        reason: parse_reason(&reason)?
                                                    };
                                                },
                                                "bounced" => {
                                                    self.status = Status::Bounced {
                                                        reason: parse_reason(&reason)?
                                                    };
                                                }
                                                _ => {
                                                    return Err(anyhow!("Unknown smtp status: {}", status));
                                                },
                                            }
                                        }
                                        _ => {},
                                    }
                                }
                            }
                        },
                        _ => {},
                    }
                }
            }
        }
        Ok(())
    }
}

impl Default for Message {
    fn default() -> Self {
        Message {
            log_lines: Vec::new(),
            is_in_queue: false,
            client: None,
            message_id: None,
            from: None,
            to: None,
            size: None,
            status: Status::Unknown,
        }
    }
}

fn parse_fields(input: &str) -> IResult<&str, Vec<(String, String)>> {
    map(
        separated_list1(
            tag::<&str, &str, _>(", "),
            alt((
                tuple((
                    verify(take_until1("="), |s: &str| s != "status"),
                    tag("="),
                    take_while1(|c| c != ','),
                )),
                tuple((
                    verify(take_until1("="), |s: &str| s == "status"),
                    tag("="),
                    rest,
                )),
            )),
        ),
        |fields| {
            fields
                .into_iter()
                .map(|(name, _, value)| {
                    (name.into(), value.into())
                })
                .collect()
        }
    )(input)
}

fn parse_email(input: &str) -> IResult<&str, String> {
    map(
        tuple((
            take_until::<&str, &str, _>("<"),
            tag("<"),
            take_while(|c| c != '>'),
            tag(">"),
        )),
        |(_, _, email, _)| {
            email.into()
        }
    )(input)
}

fn parse_size(input: &str) -> IResult<&str, u64> {
    map(
        nom::character::complete::u64,
        |size| {
            size
        }
    )(input)
}

fn parse_client(input: &str) -> IResult<&str, (String, String)> {
    map(
        tuple((
            take_until1::<&str, &str, _>("["),
            tag("["),
            take_until1("]"),
            tag("]"),
        )),
        |(hostname, _, ip_addr, _)| {
            (hostname.into(), ip_addr.into())
        }
    )(input)
}

fn parse_status(input: &str) -> IResult<&str, (String, String)> {
    map(
        tuple((
            alt((
                tag::<&str, &str, _>("sent"),
                tag("deferred"),
                tag("bounced"),
            )),
            multispace1,
            tag("("),
            rest,
        )),
        |(status, _, _, reason)| {
            let trimmed_reason =
                match reason.strip_suffix(")") {
                    Some(trimmed) => trimmed,
                    None => reason,
                };
            (status.into(), trimmed_reason.into())
        }
    )(input)
}
