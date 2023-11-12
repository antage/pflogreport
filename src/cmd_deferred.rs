use std::collections::BTreeMap;

use anyhow::Result;
use serde_derive::Serialize;

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
        println!("{}", serde_json::to_string(&Self::convert_reasons(&self.reasons))?);
        Ok(())
    }

    fn print_json_reasons_by_to_addr(&self) -> Result<()> {
        let m: BTreeMap<String, Vec<(T, usize)>> =
            self
                .reasons_by_to
                .iter()
                .map(|(k, v)| (k.clone(), Self::convert_reasons(v)))
                .collect();
        println!("{}", serde_json::to_string(&m)?);
        Ok(())
    }

    fn print_json_reasons_by_to_domain(&self) -> Result<()> {
        let m: BTreeMap<String, Vec<(T, usize)>> =
            self
                .reasons_by_to_domain
                .iter()
                .map(|(k, v)| (k.clone(), Self::convert_reasons(v)))
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
