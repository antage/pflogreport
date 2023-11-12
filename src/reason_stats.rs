use anyhow::Result;

pub trait ReasonStats {
    fn print_console_reasons(&self) -> Result<()>;
    fn print_console_reasons_by_to_addr(&self) -> Result<()>;
    fn print_console_reasons_by_to_domain(&self) -> Result<()>;

    fn print_json_reasons(&self) -> Result<()>;
    fn print_json_reasons_by_to_addr(&self) -> Result<()>;
    fn print_json_reasons_by_to_domain(&self) -> Result<()>;
}
