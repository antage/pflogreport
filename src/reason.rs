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
    Other(String),
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

    static DNS_ERROR_RE: [(ReasonPreParseKind, Lazy<Regex>); 2] = [
        (
            ReasonPreParseKind::Other,
            lazy_regex!("\\AHost or domain name not found\\. Name service error for name=(?P<name>[-A-Za-z0-9_.]+) type=(?P<type>[A-Z]+): Host not found(?:, try again)?\\z"),
        ),
        (
            ReasonPreParseKind::Other,
            lazy_regex!("\\AHost or domain name not found\\. Name service error for name=(?P<name>[-A-Za-z0-9_.]+) type=(?P<type>[A-Z]+): Host found but no data record of requested type\\z"),
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

    static OVER_QUOTA_TEMP_RE: [(ReasonPreParseKind, Lazy<Regex>); 1] = [
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A452-4\\.2\\.2 The email account that you tried to reach is over quota\\. Please direct 452-4\\.2\\.2 the recipient to 452 4\\.2\\.2  https://support\\.google\\.com/mail/\\?p=OverQuotaTemp [-a-z0-9z.]+ - gsmtp\\z"),
        ),
    ];
    if let Some(_) = find_any_reason(&pre_parse, &pre_parse_kind, &OVER_QUOTA_TEMP_RE) {
        let attrs = pre_parse_attrs.unwrap();
        return Ok(Reason::OverQuotaTemp {
            hostname: attrs.hostname.clone(),
            ipaddr: attrs.ipaddr,
        });
    }

    static OVER_QUOTA_PERM_RE: [(ReasonPreParseKind, Lazy<Regex>); 3] = [
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
    ];
    if let Some(_) = find_any_reason(&pre_parse, &pre_parse_kind, &OVER_QUOTA_PERM_RE) {
        let attrs = pre_parse_attrs.unwrap();
        return Ok(Reason::OverQuotaPerm {
            hostname: attrs.hostname.clone(),
            ipaddr: attrs.ipaddr,
        });
    }

    static NO_SUCH_USER_RE: [(ReasonPreParseKind, Lazy<Regex>); 15] = [
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550-5\\.1\\.1 The email account that you tried to reach does not exist\\. Please try 550-5\\.1\\.1 double-checking the recipient's email address for typos or 550-5\\.1\\.1 unnecessary spaces. Learn more at 550 5\\.1\\.1  https://support\\.google\\.com/mail/\\?p=NoSuchUser [-a-z0-9z.]+ - gsmtp\\z"),
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
            lazy_regex!("\\A554 5\\.1\\.1 <[^>]+>: Recipient address rejected: undeliverable address: .*\\z"),
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
    ];
    if let Some(_) = find_any_reason(&pre_parse, &pre_parse_kind, &NO_SUCH_USER_RE) {
        let attrs = pre_parse_attrs.unwrap();
        return Ok(Reason::NoSuchUser {
            hostname: attrs.hostname.clone(),
            ipaddr: attrs.ipaddr,
        });
    }

    static DISABLED_USER_RE: [(ReasonPreParseKind, Lazy<Regex>); 8] = [
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A550-5\\.2\\.1 The email account that you tried to reach is disabled\\. Learn more at 550 5\\.2\\.1  https://support\\.google\\.com/mail/\\?p=DisabledUser [-a-z0-9z.]+ - gsmtp\\z"),
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
    ];
    if let Some(_) = find_any_reason(&pre_parse, &pre_parse_kind, &DISABLED_USER_RE) {
        let attrs = pre_parse_attrs.unwrap();
        return Ok(Reason::DisabledUser {
            hostname: attrs.hostname.clone(),
            ipaddr: attrs.ipaddr,
        });
    }

    static UNSOLICITED_MESSAGE_ERROR_RE: [(ReasonPreParseKind, Lazy<Regex>); 4] = [
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

    static ACCESS_DENIED_1_RE: [(ReasonPreParseKind, Lazy<Regex>); 4] = [
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
    ];
    if let Some(_) = find_any_reason(&pre_parse, &pre_parse_kind, &ACCESS_DENIED_1_RE) {
        let attrs = pre_parse_attrs.unwrap();
        return Ok(Reason::AccessDenied {
            hostname: attrs.hostname.clone(),
            ipaddr: attrs.ipaddr,
        });
    }

    static ACCESS_DENIED_2_RE: [(ReasonPreParseKind, Lazy<Regex>); 1] = [
        (
            ReasonPreParseKind::Other,
            lazy_regex!("\\Ahost (?P<hostname>[-A-Za-z0-9_.]+)\\[(?P<ipaddr>[A-Fa-f0-9.:]+)\\] refused to talk to me: 554 Access Denied\\z"),
        ),
    ];
    if let Some(caps) = find_any_reason(&pre_parse, &pre_parse_kind, &ACCESS_DENIED_2_RE) {
        return Ok(Reason::AccessDenied {
            hostname: caps["hostname"].clone(),
            ipaddr: caps["ipaddr"].parse()?,
        });
    }


    static CUSTOM_DOMAIN_POLICY_RE: [(ReasonPreParseKind, Lazy<Regex>); 4] = [
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A550[- ]5\\.7\\.1 .* gcdp [-a-z0-9z.]+ - gsmtp\\z"),
        ),
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A550[- ]5\\.7\\.1 The user or domain that you are sending to \\(or from\\) has a policy that 550-5\\.7\\.1 prohibited the mail that you sent. Please contact your domain 550-5\\.7\\.1 administrator for further details. For more information, please visit 550 5\\.7\\.1  https://support\\.google\\.com/a/answer/172179 [-a-z0-9z.]+ - gsmtp\\z"),
        ),
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A451[- ]4\\.4\\.4 Mail received as unauthenticated, incoming to a recipient domain configured in a hosted tenant which has no mail-enabled subscriptions. ATTR5 \\[[^\\]]*\\]\\z"),
        ),
        (
            ReasonPreParseKind::Data,
            lazy_regex!("\\A554[- ]5\\.7\\.1 \\[HM08\\] Message rejected due to local policy. Please visit https://support\\.apple\\.com/en-us/HT204137\\z"),
        ),
    ];
    if let Some(_) = find_any_reason(&pre_parse, &pre_parse_kind, &CUSTOM_DOMAIN_POLICY_RE) {
        let attrs = pre_parse_attrs.unwrap();
        return Ok(Reason::CustomDomainPolicy {
            hostname: attrs.hostname.clone(),
            ipaddr: attrs.ipaddr,
        });
    }

    static BLOCK_LIST_1_RE: [(ReasonPreParseKind, Lazy<Regex>); 1] = [
        (
            ReasonPreParseKind::MailFrom,
            lazy_regex!("\\A553[- ]5\\.3\\.0 [^ ]* DNSBL:RBL 521< [A-Fa-f0-9.:]+ >_is_blocked.For assistance forward this error to abuse_rbl@abuse-att.net\\z"),
        ),
    ];
    if let Some(_) = find_any_reason(&pre_parse, &pre_parse_kind, &BLOCK_LIST_1_RE) {
        let attrs = pre_parse_attrs.unwrap();
        return Ok(Reason::BlockList {
            hostname: attrs.hostname.clone(),
            ipaddr: attrs.ipaddr,
        });
    }

    static BLOCK_LIST_2_RE: [(ReasonPreParseKind, Lazy<Regex>); 1] = [
        (
            ReasonPreParseKind::Other,
            lazy_regex!("\\Ahost (?P<hostname>[-A-Za-z0-9_.]+)\\[(?P<ipaddr>[A-Fa-f0-9.:]+)\\] refused to talk to me: 554 IP=[A-Fa-f0-9.:]+ - None/bad reputation\\. Ask your postmaster for help or to contact [^ ]+ for reset\\. \\(NOWL\\)\\z"),
        ),
    ];
    if let Some(caps) = find_any_reason(&pre_parse, &pre_parse_kind, &BLOCK_LIST_2_RE) {
        return Ok(Reason::BlockList {
            hostname: caps["hostname"].clone(),
            ipaddr: caps["ipaddr"].parse()?,
        });
    }

    static RELAY_ACCESS_DENIED_RE: [(ReasonPreParseKind, Lazy<Regex>); 2] = [
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A554[- ]5\\.7\\.1 <[^>]+>: Relay access denied\\z"),
        ),
        (
            ReasonPreParseKind::RcptTo,
            lazy_regex!("\\A451 relay not permitted!\\z"),
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

    Ok(Reason::Other(s.to_string()))
}
