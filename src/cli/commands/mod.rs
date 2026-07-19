mod exchange;
mod inventory;
mod refresh;
pub(super) mod scan;
pub(super) mod sources;
mod tools;

use anyhow::Result;
use fellaga_core::passive::{self, ApiKeyStore};
use std::path::PathBuf;

use super::args::{Cli, Command};
use super::runtime::default_database_path;

pub(super) struct AppContext {
    database_path: PathBuf,
    config_path: PathBuf,
    api_keys: ApiKeyStore,
    database_explicit: bool,
}

impl AppContext {
    fn from_cli(cli: &Cli) -> Result<Self> {
        let database_explicit = cli.db.is_some();
        let database_path = cli.db.clone().unwrap_or_else(default_database_path);
        let config_path = cli
            .config
            .clone()
            .unwrap_or_else(passive::default_config_path);
        let api_keys = ApiKeyStore::load_or_create(&config_path)?;
        Ok(Self {
            database_path,
            config_path,
            api_keys,
            database_explicit,
        })
    }
}

pub(super) async fn run(cli: Cli) -> Result<()> {
    let context = AppContext::from_cli(&cli)?;
    match cli.command {
        Command::Scan(args) => scan::run(args, &context).await,
        Command::List(args) => inventory::list(args, &context),
        Command::Refresh(args) => refresh::run(args, &context).await,
        Command::History(args) => inventory::history(args, &context),
        Command::Stats => inventory::stats(&context),
        Command::Cache { action } => inventory::cache(action, &context),
        Command::Knowledge(args) => inventory::knowledge(args, &context),
        Command::Sources(args) => sources::run(args, &context).await,
        Command::Explain(args) => inventory::explain(args, &context),
        Command::Benchmark { action } => tools::benchmark(action, &context).await,
        Command::Resolvers { action } => tools::resolvers(action).await,
        Command::Import(args) => exchange::import(args, &context),
        Command::Export(args) => exchange::export(args, &context),
    }
}
