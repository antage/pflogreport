use std::collections::BTreeMap;

use anyhow::Result;
use serde_derive::Serialize;
use serde_json::{Value, json};

use crate::message::{Message, Status};
use crate::reason::{Reason, ReasonKind, ReasonType};
use crate::reason_stats::ReasonStats;

#[derive(Default, Serialize)]
pub struct Deferred<T>
    where T: std::fmt::Debug + From<Reason> + ReasonType + serde::Serialize + Ord + Clone {
    reasons: BTreeMap<T, usize>,
    reasons_by_to: BTreeMap<String, BTreeMap<T, usize>>,
    reasons_by_to_domain: BTreeMap<String, BTreeMap<T, usize>>,
}

impl<T> Deferred<T>
    where T: std::fmt::Debug + From<Reason> + ReasonType + serde::Serialize + Ord + Clone
{
    fn convert_reasons(r: &BTreeMap<T, usize>) -> Vec<(T, usize)> {
        let mut s: BTreeMap<ReasonKind, Vec<(&T, usize)>> = BTreeMap::new();
        for (k, v) in r {
            s
                .entry(k.kind())
                .or_insert(Vec::new())
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
                .map(|e| (e[0].as_str().unwrap().to_string(), e[1].clone()))
                .collect();
            Value::Object(m)
        } else {
            Value::Array(arr)
        }
    }
}

impl<T> ReasonStats for Deferred<T>
    where T: std::fmt::Debug + From<Reason> + ReasonType + serde::Serialize + Ord + Clone
{
    fn print_console_reasons(&self) -> Result<()> {
        println!("All reasons:");
        for reason in &self.reasons {
            println!("\t{:10} {:?}", reason.1, reason.0);
        }
        Ok(())
    }

    fn print_console_reasons_by_to_addr(&self) -> Result<()> {
        println!("Reasons by TO address:");
        for (addr, reasons) in &self.reasons_by_to {
            println!("\t{}:", addr);
            for reason in reasons {
                println!("\t\t{:10} {:?}", reason.1, reason.0);
            }
        }
        Ok(())
    }

    fn print_console_reasons_by_to_domain(&self) -> Result<()> {
        println!("Reasons by TO domain:");
        for (domain, reasons) in &self.reasons_by_to_domain {
            println!("\t{}:", domain);
            for reason in reasons {
                println!("\t\t{:10} {:?}", reason.1, reason.0);
            }
        }
        Ok(())
    }

    fn print_json_reasons(&self) -> Result<()> {
        println!("{}", serde_json::to_string(&Self::grouped_json(&self.reasons))?);
        Ok(())
    }

    fn print_json_reasons_by_to_addr(&self) -> Result<()> {
        let m: BTreeMap<String, Value> =
            self
                .reasons_by_to
                .iter()
                .map(|(k, v)| (k.clone(), Self::grouped_json(v)))
                .collect();
        println!("{}", serde_json::to_string(&m)?);
        Ok(())
    }

    fn print_json_reasons_by_to_domain(&self) -> Result<()> {
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

impl<T> Deferred<T>
    where T: std::fmt::Debug + From<Reason> + ReasonType + serde::Serialize + Ord + Clone
{
    fn default() -> Self {
        Deferred {
            reasons: BTreeMap::new(),
            reasons_by_to: BTreeMap::new(),
            reasons_by_to_domain: BTreeMap::new(),
        }
    }

    pub fn new(logs_by_message_id: &BTreeMap<u64, Message>) -> Result<Self> {
        let mut deferred = Deferred::default();
        for (_, msg) in logs_by_message_id.iter() {
            match msg.status {
                Status::Deferred { ref reason } => {
                    let reason_kind = T::from(reason.clone());
                    if let Some(counter) = deferred.reasons.get_mut(&reason_kind) {
                        *counter += 1;
                    } else {
                        deferred.reasons.insert(reason_kind.clone(), 1);
                    }

                    if let Some(to_addr) = &msg.to {
                        let to_addr_lc = to_addr.to_lowercase();
                        match deferred.reasons_by_to.get_mut(&to_addr_lc) {
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
                                deferred.reasons_by_to.insert(to_addr_lc, reasons);
                            },
                        }

                        let to_addr_parts: Vec<&str> =
                            to_addr
                                .splitn(2, "@")
                                .collect();
                        if to_addr_parts.len() == 2 {
                            let to_domain = to_addr_parts[1].to_lowercase();
                            match deferred.reasons_by_to_domain.get_mut(&to_domain) {
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
                                    deferred.reasons_by_to_domain.insert(to_domain, reasons);
                                },
                            }
                        }
                    }
                },
                _ => {},
            }
        }

        Ok(deferred)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grouped_json_non_verbose_is_object() {
        let mut r = BTreeMap::new();
        r.insert(ReasonKind::OverQuotaPerm, 2);
        r.insert(ReasonKind::NoSuchUser, 5);
        assert_eq!(
            Deferred::<ReasonKind>::grouped_json(&r),
            json!({"OverQuotaPerm": 2, "NoSuchUser": 5})
        );
    }

    #[test]
    fn grouped_json_verbose_keeps_pairs() {
        let mut r = BTreeMap::new();
        r.insert(Reason::Other { message: "boom".into() }, 1);
        assert_eq!(
            Deferred::<Reason>::grouped_json(&r),
            json!([[{"kind": "Other", "message": "boom"}, 1]])
        );
    }
}
