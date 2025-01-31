use huginn::{
    validation::{sanitize_and_validate, Validator},
    SecurityConfig, ValidationError,
};
use regex::Regex;

// 1. Email Validator ---------------------------------------------------------
#[derive(Clone, Copy)]
struct EmailValidator;

impl Validator<String> for EmailValidator {
    fn validate(&self, input: &str) -> Result<String, ValidationError> {
        let re = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
            .expect("Invalid regex pattern");

        if re.is_match(input) {
            Ok(input.to_string())
        } else {
            Err(ValidationError::InvalidFormat {
                target_type: self.target_type(),
            })
        }
    }

    fn target_type(&self) -> &'static str {
        "email"
    }
}

// 2. Number Validator -------------------------------------------------------
#[derive(Clone, Copy)]
struct NumberValidator;

impl Validator<i32> for NumberValidator {
    fn validate(&self, input: &str) -> Result<i32, ValidationError> {
        input.parse().map_err(|_| ValidationError::InvalidFormat {
            target_type: self.target_type(),
        })
    }

    fn target_type(&self) -> &'static str {
        "i32"
    }
}

// 3. Password Validator -----------------------------------------------------
#[derive(Clone, Copy)]
struct PasswordValidator {
    min_length: usize,
    require_special: bool,
}

impl Validator<String> for PasswordValidator {
    fn validate(&self, input: &str) -> Result<String, ValidationError> {
        if input.len() < self.min_length {
            return Err(ValidationError::custom(format!(
                "Password must be at least {} characters",
                self.min_length
            )));
        }

        if self.require_special && !input.chars().any(|c| "!@#$%^&*".contains(c)) {
            return Err(ValidationError::custom(
                "Password must contain at least one special character",
            ));
        }

        Ok(input.to_string())
    }

    fn target_type(&self) -> &'static str {
        "password"
    }
}

// 4. Length Validator -------------------------------------------------------
#[derive(Clone, Copy)]
struct LengthValidator {
    max: usize,
}

impl Validator<String> for LengthValidator {
    fn validate(&self, input: &str) -> Result<String, ValidationError> {
        if input.len() > self.max {
            Err(ValidationError::custom(format!(
                "Input exceeds maximum length of {} characters",
                self.max
            )))
        } else {
            Ok(input.to_string())
        }
    }

    fn target_type(&self) -> &'static str {
        "length"
    }
}

fn main() {
    let base_config = SecurityConfig::default();

    // Email Validation
    println!("=== Testing Email Validation ===");
    let email_cases = [
        "good@example.com",
        "%3Cscript%3Ealert('Hacked!')%3C/script%3E",
        "invalid-email",
    ];

    for input in email_cases {
        let result = sanitize_and_validate(input, &EmailValidator, &base_config);
        print_result(input, result);
    }

    // Number Validation
    println!("\n=== Testing Number Validation ===");
    let number_cases = ["42", "123abc", "9876543210"];

    for input in number_cases {
        let result = sanitize_and_validate(input, &NumberValidator, &base_config);
        print_result(input, result);
    }

    // Password Validation
    println!("\n=== Testing Password Validation ===");
    let password_config = SecurityConfig::builder()
        .add_forbidden_char('$')
        .add_blocked_pattern(r"(?i)password")
        .expect("Invalid regex pattern")
        .build();

    let password_validator = PasswordValidator {
        min_length: 8,
        require_special: true,
    };

    let password_cases = ["weak", "Strong123", "SecurePass123!", "password123!"];

    for input in password_cases {
        let result = sanitize_and_validate(input, &password_validator, &password_config);
        print_result(input, result);
    }

    // Length Validation
    println!("\n=== Testing Length Validation ===");
    let length_validator = LengthValidator { max: 10 };
    let length_cases = ["short", "AAAAAAAAAAAAAAAAAAAA"];

    for input in length_cases {
        let result = sanitize_and_validate(input, &length_validator, &base_config);
        print_result(input, result);
    }
}

fn print_result<T: std::fmt::Display>(
    input: &str,
    result: Result<huginn::validation::SanitizedInput<T>, ValidationError>,
) {
    match result {
        Ok(res) => println!("[OK] '{}' => {}", input, res.cleaned),
        Err(e) => println!("[ERR] '{}' => {}", input, e),
    }
}
