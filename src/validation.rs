use super::{config::SecurityConfig, error::ValidationError};
use std::{borrow::Cow, fmt::Debug};
use urlencoding::decode;

/// Result of input processing with sanitized data
#[derive(Debug, Clone)]
pub struct SanitizedInput<T> {
    /// Original user input
    pub original: String,
    /// Cleaned and validated data
    pub cleaned: T,
}

/// Trait for thread-safe validators with async support
#[async_trait::async_trait]
pub trait Validator<T>: Send + Sync {
    /// Validates and converts cleaned input synchronously
    fn validate(&self, input: &str) -> Result<T, ValidationError>;

    /// Validates and converts cleaned input asynchronously
    async fn validate_async(&self, input: &str) -> Result<T, ValidationError> {
        Ok(self.validate(input)?)
    }

    /// Returns target type name for error reporting
    fn target_type(&self) -> &'static str;
}

/// Main processing pipeline with synchronous validation
pub fn sanitize_and_validate<T>(
    input: &str,
    validator: &impl Validator<T>,
    config: &SecurityConfig,
) -> Result<SanitizedInput<T>, ValidationError>
where
    T: Debug + Send + Sync,
{
    let decoded = decode(input).unwrap_or(Cow::Borrowed(input));
    let (cleaned, bad_chars) = sanitize_input(&decoded, config);

    if !bad_chars.is_empty() {
        let symbols = bad_chars
            .iter()
            .map(|c| format!("'{}'", c))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(ValidationError::DangerousCharacters {
            symbols,
            count: bad_chars.len(),
        });
    }

    if config.has_blocked_pattern(&cleaned) {
        return Err(ValidationError::BlockedPattern {
            pattern: "blocked pattern detected".to_string(),
        });
    }

    validator.validate(&cleaned).map(|result| SanitizedInput {
        original: input.to_string(),
        cleaned: result,
    })
}

/// Main processing pipeline with asynchronous validation
pub async fn sanitize_and_validate_async<T>(
    input: &str,
    validator: &impl Validator<T>,
    config: &SecurityConfig,
) -> Result<SanitizedInput<T>, ValidationError>
where
    T: Debug + Send + Sync,
{
    let decoded = decode(input).unwrap_or(Cow::Borrowed(input));
    let (cleaned, bad_chars) = sanitize_input(&decoded, config);

    if !bad_chars.is_empty() {
        let symbols = bad_chars
            .iter()
            .map(|c| format!("'{}'", c))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(ValidationError::DangerousCharacters {
            symbols,
            count: bad_chars.len(),
        });
    }

    if config.has_blocked_pattern(&cleaned) {
        return Err(ValidationError::BlockedPattern {
            pattern: "blocked pattern detected".to_string(),
        });
    }

    validator
        .validate_async(&cleaned)
        .await
        .map(|result| SanitizedInput {
            original: input.to_string(),
            cleaned: result,
        })
}

/// Sanitizes input using iterator optimizations
pub fn sanitize_input(input: &str, config: &SecurityConfig) -> (String, Vec<char>) {
    let mut cleaned = String::with_capacity(input.len());
    let mut bad_chars = Vec::with_capacity(8); // Предварительное выделение для типичного случая

    input.chars().for_each(|c| {
        if config.is_char_forbidden(&c) {
            bad_chars.push(c);
        } else {
            cleaned.push(c);
        }
    });

    (cleaned, bad_chars)
}
