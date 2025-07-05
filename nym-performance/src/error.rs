//! Error types for performance optimization

use thiserror::Error;

/// Performance optimization error types
#[derive(Error, Debug)]
pub enum PerformanceError {
    #[error("ZkSTARK optimization error: {0}")]
    ZkStarkOptimization(String),

    #[error("Memory optimization error: {0}")]
    MemoryOptimization(String),

    #[error("Network optimization error: {0}")]
    NetworkOptimization(String),

    #[error("Profiling error: {0}")]
    Profiling(String),

    #[error("Benchmarking error: {0}")]
    Benchmarking(String),

    #[error("Monitoring error: {0}")]
    Monitoring(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Metrics error: {0}")]
    Metrics(String),

    #[error("Allocation error: {0}")]
    Allocation(String),

    #[error("Compression error: {0}")]
    Compression(String),

    #[error("Caching error: {0}")]
    Caching(String),

    #[error("Parallelization error: {0}")]
    Parallelization(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Async task error: {0}")]
    AsyncTask(#[from] tokio::task::JoinError),

    #[error("Channel error: {0}")]
    Channel(String),

    #[error("Timeout error: {0}")]
    Timeout(String),

    #[error("Resource exhaustion: {0}")]
    ResourceExhaustion(String),

    #[error("System error: {0}")]
    System(String),

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Feature not supported: {0}")]
    NotSupported(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl PerformanceError {
    /// Create a new ZkSTARK optimization error
    pub fn zkstark_optimization<T: Into<String>>(msg: T) -> Self {
        Self::ZkStarkOptimization(msg.into())
    }

    /// Create a new memory optimization error
    pub fn memory_optimization<T: Into<String>>(msg: T) -> Self {
        Self::MemoryOptimization(msg.into())
    }

    /// Create a new network optimization error
    pub fn network_optimization<T: Into<String>>(msg: T) -> Self {
        Self::NetworkOptimization(msg.into())
    }

    /// Create a new profiling error
    pub fn profiling<T: Into<String>>(msg: T) -> Self {
        Self::Profiling(msg.into())
    }

    /// Create a new benchmarking error
    pub fn benchmarking<T: Into<String>>(msg: T) -> Self {
        Self::Benchmarking(msg.into())
    }

    /// Create a new monitoring error
    pub fn monitoring<T: Into<String>>(msg: T) -> Self {
        Self::Monitoring(msg.into())
    }

    /// Create a new configuration error
    pub fn configuration<T: Into<String>>(msg: T) -> Self {
        Self::Configuration(msg.into())
    }

    /// Create a new metrics error
    pub fn metrics<T: Into<String>>(msg: T) -> Self {
        Self::Metrics(msg.into())
    }

    /// Create a new allocation error
    pub fn allocation<T: Into<String>>(msg: T) -> Self {
        Self::Allocation(msg.into())
    }

    /// Create a new compression error
    pub fn compression<T: Into<String>>(msg: T) -> Self {
        Self::Compression(msg.into())
    }

    /// Create a new caching error
    pub fn caching<T: Into<String>>(msg: T) -> Self {
        Self::Caching(msg.into())
    }

    /// Create a new parallelization error
    pub fn parallelization<T: Into<String>>(msg: T) -> Self {
        Self::Parallelization(msg.into())
    }

    /// Create a new channel error
    pub fn channel<T: Into<String>>(msg: T) -> Self {
        Self::Channel(msg.into())
    }

    /// Create a new timeout error
    pub fn timeout<T: Into<String>>(msg: T) -> Self {
        Self::Timeout(msg.into())
    }

    /// Create a new resource exhaustion error
    pub fn resource_exhaustion<T: Into<String>>(msg: T) -> Self {
        Self::ResourceExhaustion(msg.into())
    }

    /// Create a new system error
    pub fn system<T: Into<String>>(msg: T) -> Self {
        Self::System(msg.into())
    }

    /// Create a new invalid parameter error
    pub fn invalid_parameter<T: Into<String>>(msg: T) -> Self {
        Self::InvalidParameter(msg.into())
    }

    /// Create a new not supported error
    pub fn not_supported<T: Into<String>>(msg: T) -> Self {
        Self::NotSupported(msg.into())
    }

    /// Create a new internal error
    pub fn internal<T: Into<String>>(msg: T) -> Self {
        Self::Internal(msg.into())
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            // System errors are usually not recoverable
            Self::System(_) | Self::ResourceExhaustion(_) => false,
            // Configuration errors are not recoverable
            Self::Configuration(_) | Self::InvalidParameter(_) => false,
            // Feature not supported is not recoverable
            Self::NotSupported(_) => false,
            // Internal errors are usually not recoverable
            Self::Internal(_) => false,
            // I/O errors might be recoverable
            Self::Io(_) => true,
            // Everything else is potentially recoverable
            _ => true,
        }
    }

    /// Get error category
    pub fn category(&self) -> &'static str {
        match self {
            Self::ZkStarkOptimization(_) => "zkstark",
            Self::MemoryOptimization(_) => "memory",
            Self::NetworkOptimization(_) => "network",
            Self::Profiling(_) => "profiling",
            Self::Benchmarking(_) => "benchmarking",
            Self::Monitoring(_) => "monitoring",
            Self::Configuration(_) | Self::InvalidParameter(_) => "configuration",
            Self::Metrics(_) => "metrics",
            Self::Allocation(_) => "allocation",
            Self::Compression(_) => "compression",
            Self::Caching(_) => "caching",
            Self::Parallelization(_) => "parallelization",
            Self::Io(_) => "io",
            Self::Serialization(_) => "serialization",
            Self::AsyncTask(_) => "async",
            Self::Channel(_) => "channel",
            Self::Timeout(_) => "timeout",
            Self::ResourceExhaustion(_) => "resource",
            Self::System(_) => "system",
            Self::NotSupported(_) => "support",
            Self::Internal(_) => "internal",
        }
    }
}

impl From<crossbeam_channel::RecvError> for PerformanceError {
    fn from(err: crossbeam_channel::RecvError) -> Self {
        Self::channel(format!("Channel receive error: {}", err))
    }
}

impl<T> From<crossbeam_channel::SendError<T>> for PerformanceError {
    fn from(err: crossbeam_channel::SendError<T>) -> Self {
        Self::channel(format!("Channel send error: {}", err))
    }
}

impl From<tokio::time::error::Elapsed> for PerformanceError {
    fn from(err: tokio::time::error::Elapsed) -> Self {
        Self::timeout(format!("Operation timed out: {}", err))
    }
}

/// Result type for performance operations
pub type Result<T> = std::result::Result<T, PerformanceError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let error = PerformanceError::zkstark_optimization("test error");
        assert_eq!(error.category(), "zkstark");
        assert!(error.is_recoverable());
    }

    #[test]
    fn test_error_recoverability() {
        assert!(!PerformanceError::system("test").is_recoverable());
        assert!(!PerformanceError::resource_exhaustion("test").is_recoverable());
        assert!(!PerformanceError::configuration("test").is_recoverable());
        assert!(!PerformanceError::not_supported("test").is_recoverable());
        assert!(!PerformanceError::internal("test").is_recoverable());
        
        assert!(PerformanceError::zkstark_optimization("test").is_recoverable());
        assert!(PerformanceError::memory_optimization("test").is_recoverable());
        assert!(PerformanceError::network_optimization("test").is_recoverable());
    }

    #[test]
    fn test_error_categories() {
        assert_eq!(PerformanceError::zkstark_optimization("test").category(), "zkstark");
        assert_eq!(PerformanceError::memory_optimization("test").category(), "memory");
        assert_eq!(PerformanceError::network_optimization("test").category(), "network");
        assert_eq!(PerformanceError::profiling("test").category(), "profiling");
        assert_eq!(PerformanceError::benchmarking("test").category(), "benchmarking");
        assert_eq!(PerformanceError::monitoring("test").category(), "monitoring");
        assert_eq!(PerformanceError::configuration("test").category(), "configuration");
        assert_eq!(PerformanceError::metrics("test").category(), "metrics");
    }
}