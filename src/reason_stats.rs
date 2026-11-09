use anyhow::Result;

/// How a report is written.
#[derive(Clone, Copy)]
pub enum Format {
    Console,
    Json,
}

/// What a report groups its reasons under.
#[derive(Clone, Copy)]
pub enum Grouping {
    None,
    ToAddr,
    ToDomain,
}

pub trait ReasonStats {
    /// The report the two flags ask for. A command implements this by matching on the
    /// flags, so a new `Grouping` or `Format` has to be handled everywhere before the
    /// crate compiles: a combination nobody thought of cannot fall back to a report that
    /// was not asked for.
    fn print(&self, format: Format, grouping: Grouping) -> Result<()>;
}
