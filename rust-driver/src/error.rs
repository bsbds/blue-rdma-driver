//! Error types for the RDMA driver.

use std::{fmt, io, net::AddrParseError};
use thiserror::Error;

use crate::config::ConfigError;

/// Result type for RDMA operations.
pub type Result<T> = std::result::Result<T, RdmaError>;

/// Errors that can occur in RDMA operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RdmaError {
    /// Device operation failed
    #[error("Device operation failed: {0}")]
    DeviceError(String),

    /// Invalid input parameters
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Resource not found
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Resource exhausted
    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    /// Connection error
    #[error("Connection error: {0}")]
    ConnectionError(String),

    /// Memory registration error
    #[error("Memory registration error: {0}")]
    MemoryError(String),

    /// Queue pair error
    #[error("Queue pair error: {0}")]
    QpError(String),

    /// Completion queue error
    #[error("Completion queue error: {0}")]
    CqError(String),

    /// Timeout error
    #[error("Operation timed out: {0}")]
    Timeout(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] io::Error),

    /// Address parsing error
    #[error("Address parsing error: {0}")]
    AddrParseError(#[from] AddrParseError),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    SerdeError(#[from] serde_json::Error),

    /// Unimplemented feature
    #[error("Unimplemented feature: {0}")]
    Unimplemented(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),
}

impl RdmaError {
    /// Convert to an appropriate errno value for FFI
    #[inline]
    #[must_use]
    #[allow(clippy::wildcard_enum_match_arm)]
    pub fn to_errno(&self) -> i32 {
        match *self {
            RdmaError::InvalidInput(_) => libc::EINVAL,
            RdmaError::NotFound(_) => libc::ENOENT,
            RdmaError::ResourceExhausted(_) => libc::ENOSPC,
            RdmaError::ConnectionError(_) => libc::ECONNREFUSED,
            RdmaError::MemoryError(_) => libc::ENOMEM,
            RdmaError::Timeout(_) => libc::ETIMEDOUT,
            RdmaError::IoError(ref e) => e.raw_os_error().unwrap_or(libc::EIO),
            _ => libc::EIO,
        }
    }
}

/// Convert from `io::ErrorKind` to `RdmaError`
impl From<io::ErrorKind> for RdmaError {
    #[inline]
    #[allow(clippy::wildcard_enum_match_arm)]
    fn from(kind: io::ErrorKind) -> Self {
        match kind {
            io::ErrorKind::NotFound => RdmaError::NotFound("Resource not found".into()),
            io::ErrorKind::PermissionDenied => RdmaError::DeviceError("Permission denied".into()),
            io::ErrorKind::ConnectionRefused => {
                RdmaError::ConnectionError("Connection refused".into())
            }
            io::ErrorKind::ConnectionReset => RdmaError::ConnectionError("Connection reset".into()),
            io::ErrorKind::ConnectionAborted => {
                RdmaError::ConnectionError("Connection aborted".into())
            }
            io::ErrorKind::NotConnected => RdmaError::ConnectionError("Not connected".into()),
            io::ErrorKind::InvalidInput => RdmaError::InvalidInput("Invalid input".into()),
            io::ErrorKind::InvalidData => RdmaError::InvalidInput("Invalid data".into()),
            io::ErrorKind::TimedOut => RdmaError::Timeout("Operation timed out".into()),
            io::ErrorKind::WriteZero => RdmaError::IoError(io::Error::new(kind, "Write zero")),
            io::ErrorKind::Interrupted => RdmaError::IoError(io::Error::new(kind, "Interrupted")),
            io::ErrorKind::Unsupported => RdmaError::Unimplemented("Unsupported operation".into()),
            _ => RdmaError::IoError(io::Error::new(kind, "Unknown I/O error")),
        }
    }
}
