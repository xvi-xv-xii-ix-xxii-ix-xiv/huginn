# 🛡️ Huginn - Secure Input Validation Library for Rust

[![Crates.io](https://img.shields.io/crates/v/Huginn.svg)](https://crates.io/crates/safeinput)
[![Docs.rs](https://docs.rs/Huginn/badge.svg)](https://docs.rs/Huginn)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A high-performance, thread-safe input validation library with multi-level security checks
and customizable sanitization rules. Designed for secure handling of user-provided data
in mission-critical applications.

## Features ✨

- **Military-grade sanitization**  
  Block XSS, SQLi, path traversal, and other injection attacks
- **Zero-copy processing**  
  Optimized for maximum performance with minimal allocations
- **Thread-safe architecture**  
  Built with `Arc` and `Send + Sync` for concurrent workloads
- **Custom rule engine**  
  Create domain-specific validation logic with trait-based system
- **Smart encoding detection**  
  Auto-handle URL-encoded and hex-encoded payloads
- **Serde integration**  
  (Optional) Serialize/deserialize validation results

## Installation 📦

Add to your `Cargo.toml`:
```toml
[dependencies]
huginn = "0.9.0-rc.1"
# For serde support:
huginn = { version = "0.9.0-rc.1", features = ["serde"] }
```

## Usage

### Basic Validation

```rust
use safeinput::{SecurityConfig, ValidationError, validation::{Validator, sanitize_and_validate}};

struct EmailValidator;

impl Validator<String> for EmailValidator {
    fn validate(&self, input: &str) -> Result<String, ValidationError> {
        // Custom validation logic
        if input.contains('@') {
            Ok(input.to_string())
        } else {
            Err(ValidationError::InvalidFormat {
                target_type: "email"
            })
        }
    }

    fn target_type(&self) -> &'static str {
        "email"
    }
}

fn main() {
    let config = SecurityConfig::default();
    let input = "user@example.com";

    match sanitize_and_validate(input, &EmailValidator, &config) {
        Ok(result) => println!("Valid: {}", result.cleaned),
        Err(e) => eprintln!("Validation failed: {}", e),
    }
}
```

### Advanced Configuration

```rust
let config = SecurityConfig::builder()
    .add_forbidden_char('$')
    .add_blocked_pattern(r"(?i)password")
    .expect("Invalid regex pattern")
    .build();

let input = "P@ssw0rd123!";
let validator = PasswordValidator::new(12, true);

sanitize_and_validate(input, &validator, &config)?;
```

## Validation Pipeline 🔄

1. Input Decoding
   - Auto-detect and decode URL/hex encoding
2. Sanitization
   - Remove forbidden characters using pattern matching
3. Pattern Blocking
   - Check against 50+ built-in dangerous patterns
4. Custom Validation
   - Execute domain-specific validation rules
5. Result Packaging
   - Return both original and sanitized data

## Documentation 📚

Full API reference available on docs.rs

## License 📄

MIT License - See LICENSE for details
