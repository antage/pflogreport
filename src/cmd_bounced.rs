use std::collections::BTreeMap;

use anyhow::Result;
use serde_derive::Serialize;
use serde_json::{Value, json};

use pflogreport::message::{Message, Status};
use pflogreport::reason::{Reason, ReasonKind, ReasonType};
use pflogreport::reason_stats::{
    Format,
    Grouping,
    ReasonStats,
};

#[derive(Default, Serialize)]
pub struct Bounced<T>
    where T: std::fmt::Debug + From<Reason> + ReasonType + serde::Serialize + Ord + Clone {
    reasons: BTreeMap<T, usize>,
    reasons_by_to: BTreeMap<String, BTreeMap<T, usize>>,
    reasons_by_to_domain: BTreeMap<String, BTreeMap<T, usize>>,
}

impl<T> Bounced<T>
    where T: std::fmt::Debug + From<Reason> + ReasonType + serde::Serialize + Ord + Clone
{
    fn convert_reasons(r: &BTreeMap<T, usize>) -> Vec<(T, usize)> {
        let mut s: BTreeMap<ReasonKind, Vec<(&T, usize)>> = BTreeMap::new();
        for (k, v) in r {
            s
                .entry(k.kind())
                .or_default()
                .push((k, *v));
        }
        s.into_values().flatten().map(|(k, v)| (k.clone(), v)).collect()
    }

    // {"kind": count} when the reason serializes to a string (non-verbose),
    // [[reason, count], ...] otherwise (verbose reasons are objects and cannot be keys).
    fn grouped_json(r: &BTreeMap<T, usize>) -> Value {
        let arr: Vec<Value> = Self::convert_reasons(r)
            .iter()
            .map(|(reason, count)| json!([reason, count]))
            .collect();
        if arr.iter().all(|entry| entry[0].is_string()) {
            let m: serde_json::Map<String, Value> = arr
                .into_iter()
                .map(|e| (e[0].as_str().expect("every entry[0] is a string, checked above").to_string(), e[1].clone()))
                .collect();
            Value::Object(m)
        } else {
            Value::Array(arr)
        }
    }
}

impl<T> ReasonStats for Bounced<T>
    where T: std::fmt::Debug + From<Reason> + ReasonType + serde::Serialize + Ord + Clone
{
    fn print(&self, format: Format, grouping: Grouping) -> Result<()> {
        match (format, grouping) {
            (Format::Console, Grouping::None) => self.console_reasons(),
            (Format::Console, Grouping::ToAddr) => self.console_by_to_addr(),
            (Format::Console, Grouping::ToDomain) => self.console_by_to_domain(),
            (Format::Json, Grouping::None) => self.json_reasons(),
            (Format::Json, Grouping::ToAddr) => self.json_by_to_addr(),
            (Format::Json, Grouping::ToDomain) => self.json_by_to_domain(),
        }
    }
}


impl<T> Bounced<T>
    where T: std::fmt::Debug + From<Reason> + ReasonType + serde::Serialize + Ord + Clone
{
    fn console_reasons(&self) -> Result<()> {
        println!("All reasons:");
        for reason in &self.reasons {
            println!("\t{:10} {:?}", reason.1, reason.0);
        }
        Ok(())
    }

    fn console_by_to_addr(&self) -> Result<()> {
        println!("Reasons by TO address:");
        for (addr, reasons) in &self.reasons_by_to {
            println!("\t{}:", addr);
            for reason in reasons {
                println!("\t\t{:10} {:?}", reason.1, reason.0);
            }
        }
        Ok(())
    }

    fn console_by_to_domain(&self) -> Result<()> {
        println!("Reasons by TO domain:");
        for (domain, reasons) in &self.reasons_by_to_domain {
            println!("\t{}:", domain);
            for reason in reasons {
                println!("\t\t{:10} {:?}", reason.1, reason.0);
            }
        }
        Ok(())
    }

    fn json_reasons(&self) -> Result<()> {
        println!("{}", serde_json::to_string(&Self::grouped_json(&self.reasons))?);
        Ok(())
    }

    fn json_by_to_addr(&self) -> Result<()> {
        let m: BTreeMap<String, Value> =
            self
                .reasons_by_to
                .iter()
                .map(|(k, v)| (k.clone(), Self::grouped_json(v)))
                .collect();
        println!("{}", serde_json::to_string(&m)?);
        Ok(())
    }

    fn json_by_to_domain(&self) -> Result<()> {
        let m: BTreeMap<String, Value> =
            self
                .reasons_by_to_domain
                .iter()
                .map(|(k, v)| (k.clone(), Self::grouped_json(v)))
                .collect();
        println!("{}", serde_json::to_string(&m)?);
        Ok(())
    }
}


impl<T> Bounced<T>
    where T: std::fmt::Debug + From<Reason> + ReasonType + serde::Serialize + Ord + Clone
{
    fn default() -> Bounced<T> {
        Bounced {
            reasons: BTreeMap::new(),
            reasons_by_to: BTreeMap::new(),
            reasons_by_to_domain: BTreeMap::new(),
        }
    }

    pub fn new(logs_by_message_id: &BTreeMap<u64, Message>) -> Result<Self> {
        let mut bounced = Bounced::default();
        for msg in logs_by_message_id.values() {
            match &msg.status {
                Status::Bounced { reason } => {
                    let reason_kind = T::from(reason.clone());
                    if let Some(counter) = bounced.reasons.get_mut(&reason_kind) {
                        *counter += 1;
                    } else {
                        bounced.reasons.insert(reason_kind.clone(), 1);
                    }

                    if let Some(to_addr) = &msg.to {
                        match bounced.reasons_by_to.get_mut(to_addr) {
                            Some(reasons) => {
                                if let Some(counter) = reasons.get_mut(&reason_kind) {
                                    *counter += 1;
                                } else {
                                    reasons.insert(reason_kind.clone(), 1);
                                }
                            },
                            None => {
                                let mut reasons = BTreeMap::new();
                                reasons.insert(reason_kind.clone(), 1);
                                bounced.reasons_by_to.insert(to_addr.clone(), reasons);
                            },
                        }

                        // The domain is folded where the address is recorded, so the
                        // key here needs no normalizing of its own.
                        if let Some((_, to_domain)) = to_addr.rsplit_once('@') {
                            match bounced.reasons_by_to_domain.get_mut(to_domain) {
                                Some(reasons) => {
                                    if let Some(counter) = reasons.get_mut(&reason_kind) {
                                        *counter += 1;
                                    } else {
                                        reasons.insert(reason_kind.clone(), 1);
                                    }
                                },
                                None => {
                                    let mut reasons = BTreeMap::new();
                                    reasons.insert(reason_kind.clone(), 1);
                                    bounced.reasons_by_to_domain
                                        .insert(to_domain.to_string(), reasons);
                                },
                            }
                        }
                    }
                },
                // The other statuses are listed instead of a catch-all: a variant added
                // to Status has to be thought of here, not skipped in silence.
                Status::Unknown | Status::Sent { .. } | Status::Deferred { .. } => {},
            }
        }

        Ok(bounced)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pflogreport::log_line::LogLine;

    #[test]
    fn grouped_json_non_verbose_is_object() {
        let mut r = BTreeMap::new();
        r.insert(ReasonKind::OverQuotaPerm, 2);
        r.insert(ReasonKind::NoSuchUser, 5);
        assert_eq!(
            Bounced::<ReasonKind>::grouped_json(&r),
            json!({"OverQuotaPerm": 2, "NoSuchUser": 5})
        );
    }

    #[test]
    fn grouped_json_verbose_keeps_pairs() {
        let mut r = BTreeMap::new();
        r.insert(Reason::Other { message: "boom".into() }, 1);
        assert_eq!(
            Bounced::<Reason>::grouped_json(&r),
            json!([[{"kind": "Other", "message": "boom"}, 1]])
        );
    }

    // One recipient in two spellings. The domain is folded where the address is
    // recorded, so the two messages share a domain key, while their address keys stay
    // apart: without folding in virtual_alias_maps, Postfix delivers `John@x` and
    // `john@x` to different mailboxes.
    fn bounced_message(queue_id: &str, to: &str) -> (u64, Message) {
        let line = format!(
            "Dec 17 00:03:02 s1 postfix/smtp[123]: {}: to=<{}>, relay=mx.example.com[192.0.2.7]:25, delay=1, delays=1/1/1/1, dsn=5.1.1, status=bounced (host mx.example.com[192.0.2.7] said: 550 5.1.1 <{}>: user not found (in reply to RCPT TO command))",
            queue_id, to, to
        );
        let (_, parsed) = LogLine::parse(line.as_bytes()).unwrap();
        let id = parsed.message_id.expect("the line built above carries a queue ID");
        let mut msg = Message { log_lines: vec![parsed], ..Default::default() };
        msg.analyze().unwrap();
        (id, msg)
    }

    #[test]
    fn domain_grouping_folds_case_and_address_grouping_does_not() {
        let mut messages = BTreeMap::new();
        messages.extend([
            bounced_message("A1B2C3D4E5", "John@Mail.EXAMPLE.com"),
            bounced_message("A1B2C3D4E6", "john@mail.example.com"),
        ]);
        let bounced = Bounced::<ReasonKind>::new(&messages).unwrap();
        assert_eq!(
            bounced.reasons_by_to_domain.keys().collect::<Vec<_>>(),
            vec!["mail.example.com"]
        );
        assert_eq!(
            bounced.reasons_by_to.keys().collect::<Vec<_>>(),
            vec!["John@mail.example.com", "john@mail.example.com"]
        );
        assert_eq!(bounced.reasons_by_to_domain["mail.example.com"].values().sum::<usize>(), 2);
    }
}
