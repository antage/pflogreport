use std::collections::BTreeMap;

use anyhow::Result;
use serde_derive::Serialize;

use crate::message::{Message, Status};

#[derive(Default, Serialize)]
pub struct Stats {
    unknown: usize,
    sent: usize,
    deferred: usize,
    bounced: usize,
}

impl Stats {
    pub fn print_console(&self) -> Result<()> {
        println!("Stats:");
        println!("\tUnknown = {}", self.unknown);
        println!("\tSent = {}", self.sent);
        println!("\tDeferred = {}", self.deferred);
        println!("\tBounced = {}", self.bounced);
        Ok(())
    }

    pub fn print_json(&self) -> Result<()> {
        println!("{}", serde_json::to_string(self)?);
        Ok(())
    }
}

pub fn stats(logs_by_message_id: &BTreeMap<u64, Message>) -> Result<Stats> {
    let mut stats = Stats::default();
    for (_, msg) in logs_by_message_id.iter() {
        match msg.status {
            Status::Unknown => { stats.unknown += 1 },
            Status::Sent { .. } => { stats.sent += 1 },
            Status::Deferred { .. } => { stats.deferred += 1 },
            Status::Bounced { .. } => { stats.bounced += 1},
        }
    }

    Ok(stats)
}
