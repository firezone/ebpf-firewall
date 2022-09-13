use std::io;

use aya::{
    maps::{perf::PerfBufferError, MapError},
    programs::ProgramError,
    BpfError,
};
use thiserror::Error;

#[non_exhaustive]
#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    RuleEntryError(#[from] firewall_common::RuleStoreError),
    // Aya's error seems clear enough to just let them bubble up
    #[error(transparent)]
    MapError(#[from] MapError),
    #[error(transparent)]
    ProgramError(#[from] ProgramError),
    #[error(transparent)]
    BpfError(#[from] BpfError),
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error(transparent)]
    PerfBufferError(#[from] PerfBufferError),
    #[error("Port range is invalid")]
    InvalidPort,
}
