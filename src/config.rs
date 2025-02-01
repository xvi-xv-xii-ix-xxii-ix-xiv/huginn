use lazy_static::lazy_static;
use regex::Regex;
use std::{collections::HashSet, sync::Arc};

lazy_static! {
    static ref DEFAULT_PATTERNS: Vec<Regex> = {
        vec![
            Regex::new(r"(?i)(drop\s+table|delete\s+from|insert\s+into|select\s+\*)").unwrap(),
            Regex::new(r"(\.\./|\\x[0-9a-f]{2}|<script>|javascript:).*").unwrap(),
            Regex::new(r"(?:%[0-9a-fA-F]{2})+").unwrap(),
        ]
    };
}

/// Security configuration parameters
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Set of forbidden characters
    pub forbidden_chars: Arc<HashSet<char>>,
    /// Compiled regular expressions for blocking dangerous patterns
    pub blocked_patterns: Arc<Vec<Regex>>,
}

impl Default for SecurityConfig {
    /// Creates default configuration with recommended security settings
    fn default() -> Self {
        Self::builder()
            .with_default_forbidden_chars()
            .with_default_blocked_patterns()
            .build()
    }
}

impl SecurityConfig {
    /// Creates a new configuration builder
    pub fn builder() -> SecurityConfigBuilder {
        SecurityConfigBuilder::new()
    }

    /// Checks if character is forbidden
    #[inline(always)]
    pub fn is_char_forbidden(&self, c: &char) -> bool {
        self.forbidden_chars.contains(c)
    }

    /// Checks if input matches any blocked pattern
    pub fn has_blocked_pattern(&self, input: &str) -> bool {
        self.blocked_patterns.iter().any(|re| re.is_match(input))
    }
}

/// Builder pattern for SecurityConfig
#[derive(Debug, Default)]
pub struct SecurityConfigBuilder {
    forbidden_chars: HashSet<char>,
    blocked_patterns: Vec<Regex>,
}

impl SecurityConfigBuilder {
    /// Creates new empty builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds default forbidden characters
    pub fn with_default_forbidden_chars(mut self) -> Self {
        self.forbidden_chars
            .extend(['<', '>', '&', '\'', '"', '\\', ';', '`']);
        self
    }

    /// Adds default blocked patterns
    pub fn with_default_blocked_patterns(mut self) -> Self {
        self.blocked_patterns.extend(DEFAULT_PATTERNS.clone());
        self
    }

    /// Adds a forbidden character
    pub fn add_forbidden_char(mut self, c: char) -> Self {
        self.forbidden_chars.insert(c);
        self
    }

    /// Adds a blocked pattern
    pub fn add_blocked_pattern(mut self, pattern: &str) -> Result<Self, regex::Error> {
        self.blocked_patterns.push(Regex::new(pattern)?);
        Ok(self)
    }

    /// Finalizes the configuration
    pub fn build(self) -> SecurityConfig {
        SecurityConfig {
            forbidden_chars: Arc::new(self.forbidden_chars),
            blocked_patterns: Arc::new(self.blocked_patterns),
        }
    }
}
