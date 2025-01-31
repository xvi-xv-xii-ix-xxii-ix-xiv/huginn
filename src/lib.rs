#![warn(missing_docs)]
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

//! # Safe Input Library
//!
//! A thread-safe library for secure user input processing with support for:
//! - Multi-level validation
//! - High-performance data sanitization
//! - Customizable security rules
//! - Concurrent processing capabilities

/// Module for configuring security parameters
pub mod config;

/// Module for handling validation errors
pub mod error;

/// Core module for validation and sanitization
pub mod validation;

// Re-exporting core types
pub use config::SecurityConfig;
pub use error::ValidationError;
pub use validation::{sanitize_and_validate, SanitizedInput, Validator};
