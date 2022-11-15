use std::io;

use aya::{
    maps::{perf::PerfBufferError, MapError},
    programs::ProgramError,
    BpfError,
};
use thiserror::Error;

/// Firewall errors.
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum Error {
    /// Error when trying to store the given Rule in eBPF.
    /// Normally, space exhaustion.
    #[error(transparent)]
    RuleEntryError(#[from] firewall_common::RuleStoreError),
    // Aya's error seems clear enough to just let them bubble up
    /// Error when inserting into ebpf map.
    #[error(transparent)]
    MapError(#[from] MapError),
    /// Error while loading eBPF program.
    #[error(transparent)]
    ProgramError(#[from] ProgramError),
    /// eBPF-related error
    #[error(transparent)]
    BpfError(#[from] BpfError),
    /// IO error
    #[error(transparent)]
    IoError(#[from] io::Error),
    /// Error while reading buffers for logging.
    #[error(transparent)]
    PerfBufferError(#[from] PerfBufferError),
    /// Port range for rule is not valid.
    #[error("Port range is invalid")]
    InvalidPort,
    /// Used 0 as id number.
    #[error("Id number is not valid, must be greater than 0")]
    InvalidId,
    /// Id doesn't exist in the classifier.
    #[error("Id not stored in classifier")]
    NotExistingId,
    #[error("Packet format is erroneous for logging")]
    LogFormatError,
}
