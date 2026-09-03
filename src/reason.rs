use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::Result;
use enum_kinds::EnumKind;
use lazy_regex::{
    lazy_regex,
    Lazy,
    Regex,
};
use serde_derive::Serialize;

pub trait ReasonType {
    fn kind(&self) -> ReasonKind;
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, EnumKind)]
#[enum_kind(ReasonKind, derive(PartialOrd, Ord, Serialize))]
#[serde(tag = "kind")]
pub enum Reason {
    DNSError {
        name: String,
        _type: String,
    },
    ConnectionTimedOut {
        hostname: String,
        ipaddr: IpAddr,
        port: u16,
    },
    ConnectionRefused {
        hostname: String,
        ipaddr: IpAddr,
        port: u16,
    },
    LostConnection {
        hostname: String,
        ipaddr: IpAddr,
        _while: String,
    },
    OverQuotaTemp {
        hostname: String,
        ipaddr: IpAddr,
    },
    OverQuotaPerm {
        hostname: String,
        ipaddr: IpAddr,
    },
    NoSuchUser {
        hostname: String,
        ipaddr: IpAddr,
    },
    DisabledUser {
        hostname: String,
        ipaddr: IpAddr,
    },
    UnsolicitedMessageError {
        hostname: String,
        ipaddr: IpAddr,
        from_ipaddr: Option<IpAddr>,
    },
    AccessDenied {
        hostname: String,
        ipaddr: IpAddr,
    },
    CustomDomainPolicy {
        hostname: String,
        ipaddr: IpAddr,
    },
    BlockList {
        hostname: String,
        ipaddr: IpAddr,
    },
    RelayAccessDenied {
        hostname: String,
        ipaddr: IpAddr,
    },
    BadReverseDNS {
        hostname: String,
        ipaddr: IpAddr,
    },
    BadMX {
        domain: String,
    },
    Other {
        message: String,
    },
}

impl ReasonType for Reason {
    fn kind(&self) -> ReasonKind {
        ReasonKind::from(self)
    }
}

impl ReasonType for ReasonKind {
    fn kind(&self) -> ReasonKind {
        self.clone()
    }
}

struct ReasonCommandAttributes {
    hostname: String,
    ipaddr: IpAddr,
    message: String,
}

#[derive(EnumKind)]
#[enum_kind(ReasonPreParseKind)]
enum ReasonPreParse {
    RcptTo(ReasonCommandAttributes),
    MailFrom(ReasonCommandAttributes),
    Data(ReasonCommandAttributes),
    Other(String),
}

impl ReasonPreParse {
    fn message(&self) -> &str {
        match self {
            ReasonPreParse::RcptTo(a) => a.message.as_str(),
            ReasonPreParse::MailFrom(a) => a.message.as_str(),
            ReasonPreParse::Data(a) => a.message.as_str(),
            ReasonPreParse::Other(s) => s.as_str(),
        }
    }

    fn attributes(&self) -> Option<&ReasonCommandAttributes> {
        match self {
            ReasonPreParse::RcptTo(a) => Some(a),
            ReasonPreParse::MailFrom(a) => Some(a),
            ReasonPreParse::Data(a) => Some(a),
            ReasonPreParse::Other(_) => None,

        }
    }
}

fn pre_parse_reason(s: &str) -> Result<ReasonPreParse> {
    static CMD: Lazy<Regex> = lazy_regex!("\\Ahost (?P<hostname>[-A-Za-z0-9_.]+)\\[(?P<ipaddr>[A-Fa-f0-9.:]+)\\] said: (?P<message>.*) \\(in reply to(?: end of)? (?<command>RCPT TO|MAIL FROM|DATA) command\\)\\z");
    if let Some(caps) = CMD.captures(s) {
        match &caps["command"] {
            "RCPT TO" => {
                Ok(
                    ReasonPreParse::RcptTo(
                        ReasonCommandAttributes {
                            hostname: caps["hostname"].to_lowercase(),
                            ipaddr: caps["ipaddr"].parse()?,
                            message: caps["message"].to_string(),
                        }
                    )
                )
            },
            "MAIL FROM" => {
                Ok(
                    ReasonPreParse::MailFrom(
                        ReasonCommandAttributes {
                            hostname: caps["hostname"].to_lowercase(),
                            ipaddr: caps["ipaddr"].parse()?,
                            message: caps["message"].to_string(),
                        }
                    )
                )
            },
            "DATA" => {
                Ok(
                    ReasonPreParse::Data(
                        ReasonCommandAttributes {
                            hostname: caps["hostname"].to_lowercase(),
                            ipaddr: caps["ipaddr"].parse()?,
                            message: caps["message"].to_string(),
                        }
                    )
                )
            },
            _ => Ok(ReasonPreParse::Other(s.to_string())),
        }
    } else {
        Ok(ReasonPreParse::Other(s.to_string()))
    }
}

fn find_any_reason<'a>(pre_parse: &ReasonPreParse, pre_parse_kind: &ReasonPreParseKind, patterns: &[(ReasonPreParseKind, Lazy<Regex>)]) -> Option<HashMap<String, String>> {
    patterns
        .into_iter()
        .filter(|(kind, _)| kind == pre_parse_kind)
        .find_map(|(_, re)| {
            if let Some(caps) = re.captures(pre_parse.message()) {
                let mut groups = HashMap::new();
                for cap_name in re.capture_names() {
                    if let Some(name) = cap_name {
                        groups.insert(name.to_string(), caps[name].to_string());
                    }
                }
                Some(groups)
            } else {
                None
            }
        })
}

pub fn parse_reason(s: &str) -> Result<Reason> {
    let pre_parse = pre_parse_reason(s)?;
    let pre_parse_kind = ReasonPreParseKind::from(&pre_parse);
    let pre_parse_attrs = pre_parse.attributes();

    static DNS_ERROR_RE: [(ReasonPreParseKind, Lazy<Regex>); 3] = [
        (
            ReasonPreParseKind::Other,
            lazy_regex!("\\AHost or domain name not found\\. Name service error for name=(?P<name>[-A-Za-z0-9_.]+) type=(?P<type>[A-Z]+): Host not found(?:, try again)?\\z"),
        ),
        (
            ReasonPreParseKind::Other,
            lazy_regex!("\\AHost or domain name not found\\. Name service error for name=(?P<name>[-A-Za-z0-9_.]+) type=(?P<type>[A-Z]+): Host found but no data record of requested type\\z"),
        ),
        (
            ReasonPreParseKind::Other,
            lazy_regex!("\\AName service error for name=(?P<name>[-A-Za-z0-9_.]+) type=(?P<type>[A-Z]+): Malformed or unexpected name server reply\\z"),
        ),
    ];
    if let Some(caps) = find_any_reason(&pre_parse, &pre_parse_kind, &DNS_ERROR_RE) {
        return Ok(
            Reason::DNSError {
                name: caps["name"].clone(),
                _type: caps["type"].clone(),
            }
        )
    };

    static CONNECTION_TIMED_OUT_RE: [(ReasonPreParseKind, Lazy<Regex>); 1] = [
        (
            ReasonPreParseKind::Other,
            lazy_regex!("\\Aconnect to (?P<hostname>[-A-Za-z0-9_.]+)\\[(?P<ipaddr>[A-Fa-f0-9.:]+)\\]:(?P<port>[0-9]+): Connection timed out\\z"),
        )
    ];
    if let Some(caps) = find_any_reason(&pre_parse, &pre_parse_kind, &CONNECTION_TIMED_OUT_RE) {
        return Ok(Reason::ConnectionTimedOut {
            hostname: caps["hostname"].to_lowercase(),
            ipaddr: caps["ipaddr"].parse()?,
            port: caps["port"].parse()?,
        });
    }

    static CONNECTION_REFUSED_RE: [(ReasonPreParseKind, Lazy<Regex>); 1] = [
        (
            ReasonPreParseKind::Other,
            lazy_regex!("\\Aconnect to (?P<hostname>[-A-Za-z0-9_.]+)\\[(?P<ipaddr>[A-Fa-f0-9.:]+)\\]:(?P<port>[0-9]+): Connection refused\\z"),
        )
    ];
    if let Some(caps) = find_any_reason(&pre_parse, &pre_parse_kind, &CONNECTION_REFUSED_RE) {
        return Ok(Reason::ConnectionRefused {
            hostname: caps["hostname"].to_lowercase(),
            ipaddr: caps["ipaddr"].parse()?,
            port: caps["port"].parse()?,
        });
    }

    static LOST_CONNECTION_RE: [(ReasonPreParseKind, Lazy<Regex>); 1] = [
        (
            ReasonPreParseKind::Other,
            lazy_regex!("\\Alost connection with (?P<hostname>[-A-Za-z0-9_.]+)\\[(?P<ipaddr>[A-Fa-f0-9.:]+)\\] while (?P<while>.*)\\z"),
        )
    ];
    if let Some(caps) = find_any_reason(&pre_parse, &pre_parse_kind, &LOST_CONNECTION_RE) {
        return Ok(Reason::LostConnection {
            hostname: caps["hostname"].to_lowercase(),
            ipaddr: caps["ipaddr"].parse()?,
            _while: caps["while"].to_string(),
        });
    }

    static OVER_QUOTA_TEMP_RE: [(ReasonPreParseKind, Lazy<Regex>); 3] = [
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A452-4\\.2\\.2 The email account that you tried to reach is over quota\\. Please direct 452-4\\.2\\.2 the recipient to 452 4\\.2\\.2  https://support\\.google\\.com/mail/\\?p=OverQuotaTemp [-a-z0-9z.]+ - gsmtp\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A452-4\\.2\\.2 The recipient's inbox is out of storage space\\. Please direct the 452-4\\.2\\.2 recipient to 452 4\\.2\\.2  https://support\\.google\\.com/mail/\\?p=OverQuotaTemp [-a-z0-9z.]+ - gsmtp\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A452[- ]4\\.2\\.2 <[^>]+>: Recipient address rejected: Recipient mailbox quota exceeded\\z"),
        ),
    ];
    if let Some(_) = find_any_reason(&pre_parse, &pre_parse_kind, &OVER_QUOTA_TEMP_RE) {
        let attrs = pre_parse_attrs.unwrap();
        return Ok(Reason::OverQuotaTemp {
            hostname: attrs.hostname.clone(),
            ipaddr: attrs.ipaddr,
        });
    }

    static OVER_QUOTA_PERM_RE: [(ReasonPreParseKind, Lazy<Regex>); 7] = [
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A552-5\\.2\\.2 The email account that you tried to reach is over quota and inactive\\. 552-5\\.2\\.2 Please direct the recipient to 552 5\\.2\\.2  https://support.google.com/mail/\\?p=OverQuotaPerm [-a-z0-9z.]+ - gsmtp\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A552 5\\.2\\.2 <[^>]*>: user is over quota\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550 Mailbox is full / Blocks limit exceeded / Inode limit exceeded\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A552-5\\.2\\.2 The recipient's inbox is out of storage space and inactive\\. Please 552-5\\.2\\.2 direct the recipient to 552 5\\.2\\.2  https://support\\.google\\.com/mail/\\?p=OverQuotaPerm [-a-z0-9z.]+ - gsmtp\\z"),
        ),
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A552 5\\.2\\.2 This message could not be delivered because the recipient's mailbox is full\\. Please try again later or contact the recipient directly\\. See https://senders\\.yahooinc\\.com/smtp-error-codes#mailbox-full for more information\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A552 Mailbox limit exeeded for this email address\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A552-Requested mail action aborted: exceeded storage allocation 552-Quota exceeded\\. 552 For explanation visit https://postmaster\\.gmx\\.net/en/case\\?c=r1503&i=ip&v=[A-Fa-f0-9.:]+&r=[0-9A-Za-z-]+\\z"),
        ),
    ];
    if let Some(_) = find_any_reason(&pre_parse, &pre_parse_kind, &OVER_QUOTA_PERM_RE) {
        let attrs = pre_parse_attrs.unwrap();
        return Ok(Reason::OverQuotaPerm {
            hostname: attrs.hostname.clone(),
            ipaddr: attrs.ipaddr,
        });
    }

    static NO_SUCH_USER_RE: [(ReasonPreParseKind, Lazy<Regex>); 50] = [
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550-5\\.1\\.1 The email account that you tried to reach does not exist\\. Please try 550-5\\.1\\.1 double-checking the recipient's email address for typos or 550-5\\.1\\.1 unnecessary spaces. (?:Learn more at|For more information, go to) 550 5\\.1\\.1  https://support\\.google\\.com/mail/\\?p=NoSuchUser [-a-z0-9z.]+ - gsmtp\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.1\\.1 <[^>]+>: user not found\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.1\\.1 <[^>]+>: user does not exist\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550 Requested action not taken: mailbox unavailable\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A55[04] 5\\.1\\.1 <[^>]+>: Recipient address rejected: undeliverable address: .*\\z"),
        ),
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A552 1 Requested mail action aborted, mailbox not found\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.5\\.0 Requested action not taken: mailbox unavailable \\([^)]+\\)\\.\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.1\\.1 <[^>]+>: Recipient address rejected: User unknown in virtual mailbox table\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.2\\.0 No such mailbox: <[^>]+>\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.1\\.1 <[^>]+>: Recipient address rejected: User unknown\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550 no mailbox by that name is currently available\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550 RCPT TO:<[^>]+> User unknown\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.7\\.1 <[^>]+>: Recipient address rejected: Recipient not found\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.1\\.1 Unknown recipient\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.1\\.1 <[^>]+>: Recipient address rejected: User unknown - [^ ]+\\z"),
        ),
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A550 Message was not accepted -- invalid mailbox\\.  Local mailbox [^ ]+ is unavailable: user not found\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.7\\.1 No such user! [-0-9A-Za-z]+\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.1\\.1 <[^>]+>: Recipient address rejected: Address does not exist\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.1\\.1 <[^>]+>: Recipient address rejected: Address is not configured to receive emails\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.1\\.1 User does not exist - <[^>]+>\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.1\\.0 <[^>]+> Recipient not found\\..*\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.1\\.6 user no longer on system:[^ ]+\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.1\\.1 <[^>]+>: Recipient address rejected: User unknown in relay recipient table\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.1\\.1 <[^>]+>: Recipient address rejected: User unknown in virtual alias table\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.1\\.1 <[^>]+>: Recipient address rejected: User unknown in local recipient table\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.1\\.1 User Unknown\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550 User unknown\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550 No such recipient(?: here)?\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.1\\.1 Account not found / Nie ma takiego konta, czytaj wiecej: http://l\\.int\\.pl/[0-9]+\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550 User not found\\. See http://mail\\.i\\.ua/err/[0-9]+/\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.5\\.0 Requested action not taken: mailbox unavailable\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.5\\.0 Requested action not taken: mailbox unavailable \\([^)]+\\)\\. \\[[^\\]]+\\]\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550-5\\.1\\.1 <[^>]+>: Recipient address rejected: User unknown 550 5\\.1\\.1 <[^>]+>: Adresse destinataire invalide\\. Invalid recipient\\. LPN007_416\\z"),
        ),
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A550 permanent failure for one or more recipients \\([^:]+:550 5\\.1\\.1 The email account that you tried to reach does not exist\\..*\\)\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550-Requested action not taken: mailbox unavailable 550 For explanation visit https://postmaster\\.[A-Za-z0-9.]+/en/case\\?c=r1601&i=ip&v=[A-Fa-f0-9.:]+&r=[0-9A-Za-z-]+\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550 5\\.0\\.0 -5\\.1\\.1 The email account that you tried to reach does not exist\\..*\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.1\\.1 No such user\\. For more information, go to https://help\\.naver\\.com/alias/mail/newmail10\\.naver [-0-9A-Za-z]+ - nsmtp\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550 Recipient does not exist\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550 No Such User Here\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550 Unknown user\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550 unknown user\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550 Mailbox does not exist\\.\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.1\\.1 recipient mailbox not found\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550 unrouteable address\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550 Invalid Recipient .*\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A553 <[^>]+> address unknown\\.\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550-5\\.1\\.1 [^ ]+ recipient rejected\\. Recipient does not 550 5\\.1\\.1 exist\\. [0-9A-Z]+\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550-Callout verification failed: 550 550 invalid recipient\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.1\\.1 Address does not exist\\. [0-9A-Za-z]+\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.1\\.1 Requested action not taken: mailbox unavailable\\z"),
        ),
    ];
    if let Some(_) = find_any_reason(&pre_parse, &pre_parse_kind, &NO_SUCH_USER_RE) {
        let attrs = pre_parse_attrs.unwrap();
        return Ok(Reason::NoSuchUser {
            hostname: attrs.hostname.clone(),
            ipaddr: attrs.ipaddr,
        });
    }

    static DISABLED_USER_RE: [(ReasonPreParseKind, Lazy<Regex>); 16] = [
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.2\\.1 The email account that you tried to reach is (?:disabled|inactive)\\. (?:Learn more at|For more(?: 550[- ]5\\.2\\.1 information, go to)?) 550[- ]5\\.2\\.1  https://support\\.google\\.com/mail/\\?p=DisabledUser [-a-z0-9z.]+ - gsmtp\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.2\\.1 Account disabled\\z"),
        ),
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A550 permanent failure for one or more recipients \\([^:]+:blocked\\)\\z"),
        ),
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A550 permanent failure for one or more recipients \\([^:]+:550[- ]5\\.2\\.1 The email account that you tried to reach is disabled\\. Learn more at 5\\.2\\.1 [^)]+\\)\\z"),
        ),
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A554 30 Sorry, your message to [^ ]+ cannot be delivered. This mailbox is disabled \\(554\\.30\\)\\.\\z"),
        ),
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A550 Message was not accepted -- invalid mailbox\\.  Local mailbox [^ ]+ is unavailable: account is disabled\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550 Mailbox is frozen. See https?://[^ ]+\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550 \\\"[^\\\\]+\\\": Podane konto jest zablokowane administracyjnie lub nieaktywne / This account is disabled or not yet active \\(#5\\.1\\.1\\)\\z"),
        ),
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A550 Message was not accepted -- invalid mailbox.  Local mailbox [^ ]+ is unavailable: user is terminated\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A540[- ]5\\.7\\.1 <[^>]+>: recipient address rejected: Inactive\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A450[- ]4\\.2\\.1 <[^>]+>: Recipient address rejected: this mailbox is inactive and has been disabled\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.2\\.1 user disabled; cannot receive new mail:[^ ]+\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.2\\.1 RACT [A-Fa-f0-9.:]+: Mailbox is inactive: <[^>]+>\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550 5\\.0\\.0 -5\\.2\\.1 The email account that you tried to reach is inactive\\..*\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550 Mailbox [^ ]+ is locked due to inactivity for more than [0-9]+ months\\z"),
        ),
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A550 permanent failure for one or more recipients \\([^:]+:550 5\\.2\\.1 The email account that you tried to reach is (?:disabled|inactive)\\..*\\)\\z"),
        ),
    ];
    if let Some(_) = find_any_reason(&pre_parse, &pre_parse_kind, &DISABLED_USER_RE) {
        let attrs = pre_parse_attrs.unwrap();
        return Ok(Reason::DisabledUser {
            hostname: attrs.hostname.clone(),
            ipaddr: attrs.ipaddr,
        });
    }

    static UNSOLICITED_MESSAGE_ERROR_RE: [(ReasonPreParseKind, Lazy<Regex>); 6] = [
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A550-5\\.7\\.1 \\[(?P<from_ipaddr>[A-Fa-f0-9.:]+)\\s+[0-9]+\\] Our system has detected that this 550-5\\.7\\.1 message is likely unsolicited mail. To reduce the amount of spam sent 550-5\\.7\\.1 to Gmail, this message has been blocked\\. Please visit 550-5\\.7\\.1  https://support\\.google\\.com/mail/\\?p=UnsolicitedMessageError 550 5\\.7\\.1  for more information\\. [-a-z0-9z.]+ - gsmtp\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A541 5\\.7\\.1 Mail rejected due to antispam policy\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A451 4\\.7\\.1 Mail deferred due to antispam policy\\z"),
        ),
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A554[- ]5\\.7\\.1 \\[VI-1\\] Message blocked due to spam content in the message.\\z"),
        ),
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A550 spam message rejected\\. Please visit http://help\\.mail\\.ru/notspam-support/id\\?c=[-0-9A-Za-z_]+~ or  report details to abuse@corp\\.mail\\.ru\\. Error code: [0-9A-F]+\\. ID: [0-9A-F]+\\.\\z"),
        ),
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A554[- ]5\\.7\\.1 Spam message rejected; If this is not spam contact abuse\\z"),
        ),
    ];
    if let Some(caps) = find_any_reason(&pre_parse, &pre_parse_kind, &UNSOLICITED_MESSAGE_ERROR_RE) {
        let attrs = pre_parse_attrs.unwrap();
        return Ok(Reason::UnsolicitedMessageError {
            hostname: attrs.hostname.clone(),
            ipaddr: attrs.ipaddr,
            from_ipaddr:
                caps
                    .get("from_ipaddr")
                    .map(|s| s.parse())
                    .transpose()?,
        });
    }

    static ACCESS_DENIED_1_RE: [(ReasonPreParseKind, Lazy<Regex>); 10] = [
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.4\\.1 Recipient address rejected: Access denied.(?: AS\\(\\d+\\))? \\[[^]]+\\]\\z"),
        ),
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A550 permanent failure for one or more recipients \\([^:]+:550[- ]5\\.4\\.1 Recipient address rejected: Access denied. \\[[^)]+\\)\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.7\\.1 RDENY [A-Fa-f0-9.:]+: The receiver denied your mail\\. Please contact the receiver with another way\\.: <[^>]+>\\z"),
        ),
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A550[- ]5\\.7\\.1 Service refuse\\. Veuillez essayer plus tard\\. service refused, please try later\\. LPN007_510\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.7\\.606 Access denied, banned sending IP \\[(?P<ipaddr>[A-Fa-f0-9.:]+)\\]\\. To request removal from this list please visit https://sender\\.office\\.com/ and follow the directions\\. For more information please go to  http://go\\.microsoft\\.com/fwlink/\\?LinkID=\\d+ AS\\(\\d+\\)\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.4\\.1 Recipient address rejected: Access denied\\. For more information see https://aka\\.ms/EXOSmtpErrors \\[[^\\]]+\\]\\z"),
        ),
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A550 permanent failure for one or more recipients \\([^:]+:550[- ]5\\.4\\.1 Recipient address rejected: Access denied\\. For more information see https://aka\\.ms/EXO[^)]*\\)\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A541[- ]5\\.4\\.1 Mail rejected by destination domain\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550 recipient <[^>]+> denied\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.5\\.1 Recipient rejected - [A-Z0-9_]+ - https://postmaster-oxseu\\.vadesecure\\.com/inbound_error_codes/#_403\\z"),
        ),
    ];
    if let Some(_) = find_any_reason(&pre_parse, &pre_parse_kind, &ACCESS_DENIED_1_RE) {
        let attrs = pre_parse_attrs.unwrap();
        return Ok(Reason::AccessDenied {
            hostname: attrs.hostname.clone(),
            ipaddr: attrs.ipaddr,
        });
    }

    static ACCESS_DENIED_2_RE: [(ReasonPreParseKind, Lazy<Regex>); 2] = [
        (
            ReasonPreParseKind::Other,
            lazy_regex!("\\Ahost (?P<hostname>[-A-Za-z0-9_.]+)\\[(?P<ipaddr>[A-Fa-f0-9.:]+)\\] refused to talk to me: 554 Access Denied\\z"),
        ),
        (
            ReasonPreParseKind::Other,
            lazy_regex!("\\Ahost (?P<hostname>[-A-Za-z0-9_.]+)\\[(?P<ipaddr>[A-Fa-f0-9.:]+)\\] refused to talk to me: 550 \\[S10\\] Blocked\\z"),
        ),
    ];
    if let Some(caps) = find_any_reason(&pre_parse, &pre_parse_kind, &ACCESS_DENIED_2_RE) {
        return Ok(Reason::AccessDenied {
            hostname: caps["hostname"].clone(),
            ipaddr: caps["ipaddr"].parse()?,
        });
    }


    static CUSTOM_DOMAIN_POLICY_RE: [(ReasonPreParseKind, Lazy<Regex>); 6] = [
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A550[- ]5\\.7\\.1 .* gcdp [-a-z0-9z.]+ - gsmtp\\z"),
        ),
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A550[- ]5\\.7\\.1 The user or domain that you are sending to \\(or from\\) has a policy that 550-5\\.7\\.1 prohibited the mail that you sent. Please contact your domain 550-5\\.7\\.1 administrator for further details. For more information, (?:please visit|go to) 550 5\\.7\\.1  https://support\\.google\\.com/a/answer/172179 [-a-z0-9z.]+ - gsmtp\\z"),
        ),
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A451[- ]4\\.4\\.4 Mail received as unauthenticated, incoming to a recipient domain configured in a hosted tenant which has no mail-enabled subscriptions. ATTR5 \\[[^\\]]*\\]\\z"),
        ),
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A554[- ]5\\.7\\.1 \\[HM08\\] Message rejected due to local policy. Please visit https://support\\.apple\\.com/en-us/HT204137\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A451[- ]4\\.4\\.4 Mail received as unauthenticated, incoming to a recipient domain configured in a hosted tenant which has no mail-enabled subscriptions\\. ATTR5 \\[[^\\]]*\\]\\z"),
        ),
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A554[- ]5\\.7\\.1 [A-Za-z0-9.-]+ is a closed system\\. Emails can only be sent to or received from a limited number of approved external addresses\\..*\\z"),
        ),
    ];
    if let Some(_) = find_any_reason(&pre_parse, &pre_parse_kind, &CUSTOM_DOMAIN_POLICY_RE) {
        let attrs = pre_parse_attrs.unwrap();
        return Ok(Reason::CustomDomainPolicy {
            hostname: attrs.hostname.clone(),
            ipaddr: attrs.ipaddr,
        });
    }

    static BLOCK_LIST_1_RE: [(ReasonPreParseKind, Lazy<Regex>); 2] = [
        (
            ReasonPreParseKind::MailFrom,
            lazy_regex!("\\A553[- ]5\\.3\\.0 [^ ]* DNSBL:RBL 521< [A-Fa-f0-9.:]+ >_is_blocked.For assistance forward this error to abuse_rbl@abuse-att.net\\z"),
        ),
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A450[- ]4\\.7\\.1 Mail from [A-Fa-f0-9.:]+ has been blocked by Trend Micro Email Reputation Service\\. Please see https://ers\\.trendmicro\\.com/reputations to get detailed information\\.\\z"),
        ),
    ];
    if let Some(_) = find_any_reason(&pre_parse, &pre_parse_kind, &BLOCK_LIST_1_RE) {
        let attrs = pre_parse_attrs.unwrap();
        return Ok(Reason::BlockList {
            hostname: attrs.hostname.clone(),
            ipaddr: attrs.ipaddr,
        });
    }

    static BLOCK_LIST_2_RE: [(ReasonPreParseKind, Lazy<Regex>); 2] = [
        (
            ReasonPreParseKind::Other,
            lazy_regex!("\\Ahost (?P<hostname>[-A-Za-z0-9_.]+)\\[(?P<ipaddr>[A-Fa-f0-9.:]+)\\] refused to talk to me: 554 IP=[A-Fa-f0-9.:]+ - None/bad reputation\\. Ask your postmaster for help or to contact [^ ]+ for reset\\. \\(NOWL\\)\\z"),
        ),
        (
            ReasonPreParseKind::Other,
            lazy_regex!("\\Ahost (?P<hostname>[-A-Za-z0-9_.]+)\\[(?P<ipaddr>[A-Fa-f0-9.:]+)\\] refused to talk to me: 521 5\\.5\\.0 Your IP \\[[A-Fa-f0-9.:]+\\] has been blacklisted\\. Please contact abuse@kpn\\.com for more information\\.\\z"),
        ),
    ];
    if let Some(caps) = find_any_reason(&pre_parse, &pre_parse_kind, &BLOCK_LIST_2_RE) {
        return Ok(Reason::BlockList {
            hostname: caps["hostname"].clone(),
            ipaddr: caps["ipaddr"].parse()?,
        });
    }

    static RELAY_ACCESS_DENIED_RE: [(ReasonPreParseKind, Lazy<Regex>); 6] = [
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A554[- ]5\\.7\\.1 <[^>]+>: Relay access denied\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A451 relay not permitted!\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.7\\.1 Relaying denied\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A454[- ]4\\.7\\.1 <[^>]+>: Relay access denied\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550 relay not permitted\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550[- ]5\\.7\\.64 TenantAttribution; Relay Access Denied \\[[^\\]]+\\] \\[[^\\]]+\\]\\z"),
        ),
    ];
    if let Some(_) = find_any_reason(&pre_parse, &pre_parse_kind, &RELAY_ACCESS_DENIED_RE) {
        let attrs = pre_parse_attrs.unwrap();
        return Ok(Reason::RelayAccessDenied {
            hostname: attrs.hostname.clone(),
            ipaddr: attrs.ipaddr,
        });
    }

    static BAD_REVERSE_DNS_1_RE: [(ReasonPreParseKind, Lazy<Regex>); 2] = [
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A450[- ]4\\.7\\.25 Client host rejected: cannot find your hostname, \\[[^\\]]+\\]\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550-Inconsistent/Missing DNS PTR record \\(RFC 1912 2\\.1\\) \\([^)]+\\) 550 \\[[A-Fa-f0-9.:]+\\]:\\d+\\z"),
        ),
    ];
    if let Some(_) = find_any_reason(&pre_parse, &pre_parse_kind, &BAD_REVERSE_DNS_1_RE) {
        let attrs = pre_parse_attrs.unwrap();
        return Ok(Reason::BadReverseDNS {
            hostname: attrs.hostname.clone(),
            ipaddr: attrs.ipaddr,
        });
    }

    static BAD_REVERSE_DNS_2_RE: [(ReasonPreParseKind, Lazy<Regex>); 1] = [
        (
            ReasonPreParseKind::Other,
            lazy_regex!("\\Ahost (?P<hostname>[-A-Za-z0-9_.]+)\\[(?P<ipaddr>[A-Fa-f0-9.:]+)\\] refused to talk to me: 421 Refused\\. Your reverse DNS entry does not resolve to your IP\\.\\z"),
        ),
    ];
    if let Some(caps) = find_any_reason(&pre_parse, &pre_parse_kind, &BAD_REVERSE_DNS_2_RE) {
        return Ok(Reason::BadReverseDNS {
            hostname: caps["hostname"].clone(),
            ipaddr: caps["ipaddr"].parse()?,
        });
    }

    static BAD_MX_RE: [(ReasonPreParseKind, Lazy<Regex>); 2] = [
        (
            ReasonPreParseKind::Other,
            lazy_regex!("\\ADomain (?P<domain>[-A-Za-z0-9._]+) does not accept mail \\(nullMX\\)\\z"),
        ),
        (
            ReasonPreParseKind::Other,
            lazy_regex!("\\Amail for (?P<domain>[-A-Za-z0-9._]+) loops back to myself\\z"),
        ),
    ];
    if let Some(caps) = find_any_reason(&pre_parse, &pre_parse_kind, &BAD_MX_RE) {
        return Ok(Reason::BadMX {
            domain: caps["domain"].clone(),
        });
    }

    Ok(Reason::Other { message: s.to_string() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn all_reasons() -> Vec<Reason> {
        vec![
            Reason::DNSError { name: "example.com".into(), _type: "MX".into() },
            Reason::ConnectionTimedOut {
                hostname: "mx.example.com".into(),
                ipaddr: "192.0.2.1".parse().unwrap(),
                port: 25,
            },
            Reason::ConnectionRefused {
                hostname: "mx.example.com".into(),
                ipaddr: "192.0.2.1".parse().unwrap(),
                port: 25,
            },
            Reason::LostConnection {
                hostname: "mx.example.com".into(),
                ipaddr: "192.0.2.1".parse().unwrap(),
                _while: "RCPT TO <rcpt@example.com>".into(),
            },
            Reason::OverQuotaTemp {
                hostname: "mx1.example.com".into(),
                ipaddr: "192.0.2.35".parse().unwrap(),
            },
            Reason::OverQuotaPerm {
                hostname: "mx.example.com".into(),
                ipaddr: "192.0.2.1".parse().unwrap(),
            },
            Reason::NoSuchUser {
                hostname: "mx.example.com".into(),
                ipaddr: "192.0.2.1".parse().unwrap(),
            },
            Reason::DisabledUser {
                hostname: "mx.example.com".into(),
                ipaddr: "192.0.2.1".parse().unwrap(),
            },
            Reason::UnsolicitedMessageError {
                hostname: "mx.example.com".into(),
                ipaddr: "192.0.2.35".parse().unwrap(),
                from_ipaddr: None,
            },
            Reason::AccessDenied {
                hostname: "mx.example.com".into(),
                ipaddr: "192.0.2.1".parse().unwrap(),
            },
            Reason::CustomDomainPolicy {
                hostname: "mx.example.com".into(),
                ipaddr: "192.0.2.1".parse().unwrap(),
            },
            Reason::BlockList {
                hostname: "mx.example.com".into(),
                ipaddr: "192.0.2.1".parse().unwrap(),
            },
            Reason::RelayAccessDenied {
                hostname: "mx.example.com".into(),
                ipaddr: "192.0.2.1".parse().unwrap(),
            },
            Reason::BadReverseDNS {
                hostname: "mx.example.com".into(),
                ipaddr: "192.0.2.1".parse().unwrap(),
            },
            Reason::BadMX { domain: "example.com".into() },
            Reason::Other { message: "unrecognized failure text".into() },
        ]
    }

    #[test]
    fn all_reason_variants_serialize_with_kind_tag() {
        for reason in all_reasons() {
            let value = serde_json::to_value(reason.clone())
                .expect("all Reason variants must be serializable");
            let expected_kind = format!("{:?}", ReasonKind::from(reason.clone()));
            assert_eq!(value["kind"], json!(expected_kind));
        }
    }

    #[test]
    fn other_variant_serializes_as_tagged_map_with_message() {
        let value = serde_json::to_value(Reason::Other { message: "boom".into() }).unwrap();
        assert_eq!(value, json!({ "kind": "Other", "message": "boom" }));
    }

    #[test]
    fn verbose_json_shape_with_other_serializes() {
        // Exact shape used by Bounced/Deferred print_json_reasons in verbose mode:
        // Vec<(Reason, usize)>. Previously failed for Other(newtype String).
        let items: Vec<(Reason, usize)> = all_reasons().into_iter().zip(1..).collect();
        let s = serde_json::to_string(&items).expect("verbose JSON output must serialize");
        assert!(s.contains(r#""kind":"Other""#));
        assert!(s.contains(r#""message":"unrecognized failure text""#));
    }

    #[test]
    fn reason_kind_serializes_as_plain_string() {
        // ReasonKind must serialize to a plain string: the grouped/flat JSON
        // builders rely on it to use kinds as object keys.
        let items: Vec<(ReasonKind, usize)> = vec![(ReasonKind::DNSError, 8), (ReasonKind::Other, 6)];
        assert_eq!(
            serde_json::to_string(&items).unwrap(),
            r#"[["DNSError",8],["Other",6]]"#
        );
    }

    #[test]
    fn parse_dns_error() {
        let reason = parse_reason(
            "Host or domain name not found. Name service error for name=missing.example.com type=A: Host not found",
        ).unwrap();
        assert_eq!(reason, Reason::DNSError { name: "missing.example.com".into(), _type: "A".into() });
    }

    #[test]
    fn parse_connection_timed_out() {
        let reason = parse_reason(
            "connect to mx.example.com[192.0.2.1]:25: Connection timed out",
        ).unwrap();
        assert_eq!(
            reason,
            Reason::ConnectionTimedOut {
                hostname: "mx.example.com".into(),
                ipaddr: "192.0.2.1".parse().unwrap(),
                port: 25,
            }
        );
    }

    #[test]
    fn parse_no_such_user() {
        let reason = parse_reason(
            "host mx.example.com[192.0.2.1] said: 550 5.1.1 <rcpt@example.com>: user not found (in reply to RCPT TO command)",
        ).unwrap();
        assert_eq!(
            reason,
            Reason::NoSuchUser {
                hostname: "mx.example.com".into(),
                ipaddr: "192.0.2.1".parse().unwrap(),
            }
        );
    }

    #[test]
    fn parse_over_quota_perm() {
        let reason = parse_reason(
            "host mx.example.com[192.0.2.1] said: 552 5.2.2 <rcpt@example.com>: user is over quota (in reply to RCPT TO command)",
        ).unwrap();
        assert_eq!(
            reason,
            Reason::OverQuotaPerm {
                hostname: "mx.example.com".into(),
                ipaddr: "192.0.2.1".parse().unwrap(),
            }
        );
    }

    #[test]
    fn parse_bad_mx() {
        let reason = parse_reason("Domain example.com does not accept mail (nullMX)").unwrap();
        assert_eq!(reason, Reason::BadMX { domain: "example.com".into() });
    }

    #[test]
    fn unknown_reason_kept_verbatim_in_other() {
        let input =
            "host mx.example.com[192.0.2.1] said: 554 5.9.9 something brand new (in reply to RCPT TO command)";
        let reason = parse_reason(input).unwrap();
        assert_eq!(reason, Reason::Other { message: input.to_string() });
    }

    #[test]
    fn parse_over_quota_temp_google_storage_space() {
        let reason = parse_reason(
            "host mx1.example.com[192.0.2.26] said: 452-4.2.2 The recipient's inbox is out of storage space. Please direct the 452-4.2.2 recipient to 452 4.2.2  https://support.google.com/mail/?p=OverQuotaTemp 2adb3069b0e04-5b2f62e5bf2si3023960e87.215 - gsmtp (in reply to RCPT TO command)",
        ).unwrap();
        assert_eq!(
            reason,
            Reason::OverQuotaTemp {
                hostname: "mx1.example.com".into(),
                ipaddr: "192.0.2.26".parse().unwrap(),
            }
        );
    }

    #[test]
    fn parse_over_quota_perm_google_storage_space_inactive() {
        let reason = parse_reason(
            "host mx1.example.com[192.0.2.27] said: 552-5.2.2 The recipient's inbox is out of storage space and inactive. Please 552-5.2.2 direct the recipient to 552 5.2.2  https://support.google.com/mail/?p=OverQuotaPerm 2adb3069b0e04-5b2fb18a4a3si2270840e87.228 - gsmtp (in reply to RCPT TO command)",
        ).unwrap();
        assert_eq!(
            reason,
            Reason::OverQuotaPerm {
                hostname: "mx1.example.com".into(),
                ipaddr: "192.0.2.27".parse().unwrap(),
            }
        );
    }

    #[test]
    fn parse_no_such_user_address_does_not_exist() {
        let reason = parse_reason(
            "host mx2.example.com[192.0.2.28] said: 550 5.1.1 <user@example.com>: Recipient address rejected: Address does not exist (in reply to RCPT TO command)",
        ).unwrap();
        assert_eq!(
            reason,
            Reason::NoSuchUser {
                hostname: "mx2.example.com".into(),
                ipaddr: "192.0.2.28".parse().unwrap(),
            }
        );
    }

    #[test]
    fn parse_no_such_user_unknown_in_relay_recipient_table() {
        let reason = parse_reason(
            "host mx3.example.com[192.0.2.29] said: 550 5.1.1 <user2@example.com>: Recipient address rejected: User unknown in relay recipient table (in reply to RCPT TO command)",
        ).unwrap();
        assert_eq!(
            reason,
            Reason::NoSuchUser {
                hostname: "mx3.example.com".into(),
                ipaddr: "192.0.2.29".parse().unwrap(),
            }
        );
    }

    #[test]
    fn parse_no_such_user_no_such_recipient() {
        let reason = parse_reason(
            "host mx4.example.com[192.0.2.30] said: 550 No such recipient here (in reply to RCPT TO command)",
        ).unwrap();
        assert_eq!(
            reason,
            Reason::NoSuchUser {
                hostname: "mx4.example.com".into(),
                ipaddr: "192.0.2.30".parse().unwrap(),
            }
        );
    }

    #[test]
    fn parse_access_denied_outlook_exosmtperrors() {
        let reason = parse_reason(
            "host mx5.example.com[192.0.2.31] said: 550 5.4.1 Recipient address rejected: Access denied. For more information see https://aka.ms/EXOSmtpErrors [outlook-mx.example.com 2026-09-03T05:00:00.000Z 08DEF00000000000] (in reply to RCPT TO command)",
        ).unwrap();
        assert_eq!(
            reason,
            Reason::AccessDenied {
                hostname: "mx5.example.com".into(),
                ipaddr: "192.0.2.31".parse().unwrap(),
            }
        );
    }

    #[test]
    fn parse_custom_domain_policy_google_go_to() {
        let reason = parse_reason(
            "host mx1.example.com[192.0.2.27] said: 550-5.7.1 The user or domain that you are sending to (or from) has a policy that 550-5.7.1 prohibited the mail that you sent. Please contact your domain 550-5.7.1 administrator for further details. For more information, go to 550 5.7.1  https://support.google.com/a/answer/172179 2adb3069b0e04-5b2f623eb20si3013406e87.29 - gsmtp (in reply to end of DATA command)",
        ).unwrap();
        assert_eq!(
            reason,
            Reason::CustomDomainPolicy {
                hostname: "mx1.example.com".into(),
                ipaddr: "192.0.2.27".parse().unwrap(),
            }
        );
    }

    #[test]
    fn parse_no_such_user_mailbox_unavailable_postmaster_case() {
        let reason = parse_reason(
            "host mx6.example.com[192.0.2.32] said: 550-Requested action not taken: mailbox unavailable 550 For explanation visit https://postmaster.example.com/en/case?c=r1601&i=ip&v=192.0.2.238&r=1M9F1a-1xQWNP2EtC-00ZXDV (in reply to RCPT TO command)",
        ).unwrap();
        assert_eq!(
            reason,
            Reason::NoSuchUser {
                hostname: "mx6.example.com".into(),
                ipaddr: "192.0.2.32".parse().unwrap(),
            }
        );
    }

    #[test]
    fn parse_relay_access_denied_relaying_denied() {
        let reason = parse_reason(
            "host mx7.example.com[192.0.2.33] said: 550 5.7.1 Relaying denied (in reply to RCPT TO command)",
        ).unwrap();
        assert_eq!(
            reason,
            Reason::RelayAccessDenied {
                hostname: "mx7.example.com".into(),
                ipaddr: "192.0.2.33".parse().unwrap(),
            }
        );
    }
}
