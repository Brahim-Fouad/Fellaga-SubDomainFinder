mod progress;
mod render;
mod text;

#[cfg(test)]
mod tests;

pub(crate) use progress::ConsoleProgress;
pub(crate) use render::{print_scan_findings, print_scan_summary};
pub(crate) use text::sanitize_terminal_text;
