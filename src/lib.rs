#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! # Safe Input
//! Library
//!
//! A thread-safe library for secure user input processing with support for:
//! - Multi-level validation
//! - High-performance data sanitization
//! - Customizable security rules
//! - Concurrent processing capabilities
//! - Asynchronous validation support
//!
//! ## Example: Synchronous String Validation
//!
//! This example shows how to validate a string with a maximum length synchronously:
//!
//! ```rust
//! use huginn::{SecurityConfig, sanitize_and_validate, Validator, ValidationError};
//!
//! struct LengthValidator {
//!     max: usize,
//! }
//!
//! impl Validator<String> for LengthValidator {
//!     fn validate(&self, input: &str) -> Result<String, ValidationError> {
//!         if input.len() <= self.max {
//!             Ok(input.to_string())
//!         } else {
//!             Err(ValidationError::custom("Input too long"))
//!         }
//!     }
//!
//!     fn target_type(&self) -> &'static str {
//!         "string"
//!     }
//! }
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = SecurityConfig::default();
//!     let validator = LengthValidator { max: 10 };
//!     let result = sanitize_and_validate("hello", &validator, &config)?;
//!     println!("Sanitized input: {}", result.cleaned);
//!     Ok(())
//! }
//! ```
//!
//! ## Example: Asynchronous Number Validation
//!
//! This example demonstrates custom configuration and asynchronous number validation:
//!
//! ```rust
//! use huginn::{SecurityConfig, sanitize_and_validate_async, Validator, ValidationError};
//! use async_trait::async_trait;
//!
//! struct NumberValidator;
//!
//! #[async_trait]
//! impl Validator<i32> for NumberValidator {
//!     fn validate(&self, input: &str) -> Result<i32, ValidationError> {
//!         input.parse().map_err(|_| ValidationError::InvalidFormat { target_type: self.target_type() })
//!     }
//!
//!     async fn validate_async(&self, input: &str) -> Result<i32, ValidationError> {
//!         Ok(self.validate(input)?)
//!     }
//!
//!     fn target_type(&self) -> &'static str {
//!         "i32"
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = SecurityConfig::builder()
//!         .add_forbidden_char('#')
//!         .add_blocked_pattern(r"\d{5}")?
//!         .build();
//!     let validator = NumberValidator;
//!     let result = sanitize_and_validate_async("42", &validator, &config).await?;
//!     println!("Sanitized number: {}", result.cleaned);
//!     Ok(())
//! }
//! ```

/// Module for configuring security parameters
pub mod config;

/// Module for handling validation errors
pub mod error;

/// Core module for validation and sanitization
pub mod validation;

// Re-exporting core types
pub use config::SecurityConfig;
pub use error::ValidationError;
pub use validation::{sanitize_and_validate, sanitize_and_validate_async, SanitizedInput, Validator};