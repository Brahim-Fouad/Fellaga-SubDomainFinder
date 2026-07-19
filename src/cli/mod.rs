mod args;
mod commands;
mod console;
mod imports;
mod output;
mod profile;
mod runtime;

#[cfg(test)]
mod tests;

use anyhow::Result;
use clap::Parser;

pub(crate) async fn run() -> Result<()> {
    commands::run(args::Cli::parse()).await
}
