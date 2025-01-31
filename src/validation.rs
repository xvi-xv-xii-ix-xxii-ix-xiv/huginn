use super::{config::SecurityConfig, error::ValidationError};
use std::{borrow::Cow, fmt::Debug};
use urlencoding::decode; // Добавлен недостающий импорт

/// Result of input processing with sanitized data
#[derive(Debug, Clone)]
pub struct SanitizedInput<T> {
    /// Original user input
    pub original: String,
    /// Cleaned and validated data
    pub cleaned: T,
}

/// Trait for thread-safe validators
pub trait Validator<T>: Send + Sync {
    /// Validates and converts cleaned input
    fn validate(&self, input: &str) -> Result<T, ValidationError>;

    /// Returns target type name for error reporting
    fn target_type(&self) -> &'static str;
}

/// Main processing pipeline
pub fn sanitize_and_validate<T>(
    input: &str,
    validator: &impl Validator<T>,
    config: &SecurityConfig,
) -> Result<SanitizedInput<T>, ValidationError>
where
    T: Debug + Send + Sync,
{
    let decoded = decode(input).unwrap_or_else(|_| Cow::Borrowed(input));

    let (cleaned, bad_chars) = decoded.chars().fold(
        (String::with_capacity(decoded.len()), Vec::new()),
        |(mut clean, mut bad), c| {
            if config.is_char_forbidden(&c) {
                bad.push(c);
            } else {
                clean.push(c);
            }
            (clean, bad)
        },
    );

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

    if let Some(pattern) = config
        .blocked_patterns
        .iter()
        .find(|re| re.is_match(&cleaned))
        .map(|re| re.as_str())
    {
        return Err(ValidationError::BlockedPattern {
            pattern: pattern.to_string(),
        });
    }

    validator.validate(&cleaned).map(|result| SanitizedInput {
        original: input.to_string(),
        cleaned: result,
    })
}

/// Sanitizes input using iterator optimizations
pub fn sanitize_input(input: &str, config: &SecurityConfig) -> (String, Vec<char>) {
    let mut cleaned = String::with_capacity(input.len());
    let mut bad_chars = Vec::new();

    for c in input.chars() {
        if config.is_char_forbidden(&c) {
            bad_chars.push(c);
        } else {
            cleaned.push(c);
        }
    }

    (cleaned, bad_chars)
}
