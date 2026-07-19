//! Stable contracts shared by passive sources and persistence adapters.
//!
//! These value types intentionally contain no database or transport details.
//! Keeping them at the core boundary lets source connectors report durable
//! progress without depending on the SQLite implementation.

/// Durable numeric progress for a passive connector lane. The state contains
/// only public query metadata and counters; opaque cursors, request URLs and
/// credentials are deliberately excluded from the schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassivePaginationState {
    pub contract_version: u32,
    pub query_hash: String,
    pub next_position: u64,
    pub records_seen: u64,
    pub expected_records: Option<u64>,
    pub expected_pages: Option<u64>,
    pub last_page_hash: String,
    pub last_page_records: u64,
    pub done: bool,
    pub updated_at: i64,
}

/// A validated numeric page transition. `position` is the page just decoded;
/// `next_position` is persisted in the same transaction as its observations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassivePaginationPage {
    pub position: u64,
    pub next_position: u64,
    pub records_seen: u64,
    pub expected_records: Option<u64>,
    pub expected_pages: Option<u64>,
    pub page_hash: String,
    pub page_records: u64,
}
