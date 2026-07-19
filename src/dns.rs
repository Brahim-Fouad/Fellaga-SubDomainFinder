use crate::dnssec_proof::{
    DenialSynthesis, DnssecProofAssessment, DnssecProofInput, Nsec3Proof, NsecProof, TYPE_NXNAME,
    classify_dnssec_proof,
};
use crate::model::{
    DnsBenchmarkResult, DnsRecord, ResolvedHost, ResolverMetric, ResolverTestResult,
};
use crate::network_governor::{NetworkControl, NetworkGovernor, NetworkGovernorSnapshot};
use anyhow::{Context, Result, bail};
use futures_util::{Stream, StreamExt, stream};
use hickory_net::proto::dnssec::rdata::DNSSECRData;
use hickory_net::proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_net::proto::rr::{DNSClass, Name, RData, Record};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::{DnsError, NetError};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
use hickory_resolver::proto::rr::RecordType;
use std::collections::HashMap;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{OnceCell, oneshot};

mod engine;
mod policy;
mod transport;
mod wire;

pub use engine::DnsEngine;
pub use policy::{DnsQueryResult, DnsResolutionOutcome, WildcardProbeOutcome};
pub(crate) use wire::bind_buffered_udp;

#[cfg(test)]
mod tests;
