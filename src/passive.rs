//! Passive subdomain discovery compatibility facade.
//!
//! Static source capabilities, credentials, transport, pagination, dispatch,
//! and provider implementations live in focused child modules. Existing public
//! paths remain re-exported here for downstream compatibility.

pub mod catalog;
mod config;
mod dispatch;
mod extra;
mod ip_pivot;
mod keyed_sources;
mod pagination;
mod providers;
mod public_sources;
mod runtime;
mod transport;

pub use catalog::{
    PaginationCapability, SourceMetadata, SourcePolicy, all_source_metadata, all_unique_sources,
    passive_source_evidence_family, source_metadata, source_policy, try_source_metadata,
    validate_sources,
};
pub use config::{
    ApiKeyStore, SourceStatus, automatic_sources, automatic_sources_for_profile,
    default_config_path, source_statuses,
};
pub use pagination::{
    PassiveFetchResult, PassivePageSink, PassivePaginationContext, PassivePaginationContract,
    PassivePaginationFinishSink, PassivePaginationPageSink, numeric_pagination_contract,
    numeric_pagination_contracts,
};
pub use providers::{current_commoncrawl_endpoint, seed_commoncrawl_endpoint};
pub use runtime::{
    fetch, fetch_detailed, fetch_detailed_bounded, fetch_detailed_bounded_with_limit,
    fetch_detailed_bounded_with_pagination, fetch_detailed_bounded_with_sink,
};

pub(crate) use config::sanitize_external_error;
pub(crate) use ip_pivot::{is_public_internet_address, lookup_internetdb};
pub(crate) use transport::{
    compact_external_error, external_user_agent, response_bytes_limited_to,
    with_external_target_guard,
};

// Compatibility names used by provider children. These remain private to the
// passive subsystem rather than becoming part of the crate API.
#[cfg(test)]
use catalog::{SOURCE_DEFINITIONS, SourceId, definition, environment_names};
use config::sanitize_external_message;
use pagination::{
    commit_numeric_result_page, commit_result_page, finish_numeric_pagination,
    numeric_pagination_is_complete, numeric_pagination_resume,
};
use providers::{hostname_from_url, trusted_pagination_url};
#[cfg(test)]
use runtime::enforce_source_budget_preserving_partial_with_sink;
use transport::{
    client, ensure_external_request_allowed, exhausted_rate_limit, response_bytes_limited,
    response_json, send_external, send_external_idempotent, send_external_streaming,
    send_external_streaming_idempotent, send_with_retry_for_source, throttle_external_host,
    throttle_external_source,
};

#[cfg(test)]
mod tests;
