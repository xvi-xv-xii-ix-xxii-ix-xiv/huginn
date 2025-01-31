use thiserror::Error;

/// Comprehensive validation error types
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// Input contains forbidden characters
    #[error("Input contains {count} dangerous characters: {symbols}")]
    DangerousCharacters {
        /// List of detected dangerous characters
        symbols: String,
        /// Total count of dangerous characters
        count: usize,
    },

    /// Input format mismatch
    #[error("Input format validation failed for type {target_type}")]
    InvalidFormat {
        /// Expected data type name
        target_type: &'static str,
    },

    /// Blocked pattern detected
    #[error("Input matches blocked pattern: {pattern}")]
    BlockedPattern {
        /// Pattern that triggered the block
        pattern: String,
    },

    /// Custom validation failure
    #[error("Custom validation failed: {message}")]
    Custom {
        /// Custom error message
        message: String,
    },
}

impl ValidationError {
    /// Creates custom validation error
    pub fn custom<S: Into<String>>(message: S) -> Self {
        Self::Custom {
            message: message.into(),
        }
    }
}
