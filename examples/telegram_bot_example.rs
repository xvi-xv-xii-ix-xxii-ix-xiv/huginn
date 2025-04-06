use huginn::{
    validation::{sanitize_and_validate_async, Validator},
    SecurityConfig, ValidationError,
};
use regex::Regex;
use teloxide::{prelude::*, types::Message};

// 1. Username Validator for Telegram with injection protection
#[derive(Clone)]
struct UsernameValidator;

#[async_trait::async_trait]
impl Validator<String> for UsernameValidator {
    fn validate(&self, input: &str) -> Result<String, ValidationError> {
        let re = Regex::new(r"^[a-zA-Z0-9_]{5,32}$").expect("Invalid regex pattern");
        if re.is_match(input) {
            Ok(input.to_string())
        } else {
            Err(ValidationError::InvalidFormat {
                target_type: self.target_type(),
            })
        }
    }

    fn target_type(&self) -> &'static str {
        "telegram_username"
    }
}

// 2. Phone Number Validator with injection protection
#[derive(Clone)]
struct PhoneValidator;

#[async_trait::async_trait]
impl Validator<String> for PhoneValidator {
    fn validate(&self, input: &str) -> Result<String, ValidationError> {
        let re = Regex::new(r"^\+?[1-9]\d{1,14}$").expect("Invalid regex pattern");
        if re.is_match(input) {
            Ok(input.to_string())
        } else {
            Err(ValidationError::InvalidFormat {
                target_type: self.target_type(),
            })
        }
    }

    fn target_type(&self) -> &'static str {
        "phone_number"
    }
}

// 3. Command Validator with injection protection
#[derive(Clone)]
struct CommandValidator;

#[async_trait::async_trait]
impl Validator<String> for CommandValidator {
    fn validate(&self, input: &str) -> Result<String, ValidationError> {
        let re = Regex::new(r"^/[a-zA-Z0-9_]{1,31}$").expect("Invalid regex pattern");
        if re.is_match(input) {
            Ok(input.to_string())
        } else {
            Err(ValidationError::InvalidFormat {
                target_type: self.target_type(),
            })
        }
    }

    fn target_type(&self) -> &'static str {
        "telegram_command"
    }
}

// 4. Text Message Validator with Military-grade sanitization
#[derive(Clone)]
struct TextMessageValidator;

#[async_trait::async_trait]
impl Validator<String> for TextMessageValidator {
    fn validate(&self, input: &str) -> Result<String, ValidationError> {
        // Дополнительная проверка на длину и отсутствие подозрительных последовательностей
        if input.len() > 4096 {
            // Telegram max message length
            return Err(ValidationError::Custom {
                message: "Message too long".to_string(),
            });
        }
        Ok(input.to_string())
    }

    async fn validate_async(&self, input: &str) -> Result<String, ValidationError> {
        // Асинхронная проверка может включать дополнительные проверки (например, API)
        self.validate(input)
    }

    fn target_type(&self) -> &'static str {
        "text_message"
    }
}

#[tokio::main]
async fn main() {
    let bot = Bot::from_env();

    let config = SecurityConfig::builder()
        .with_default_forbidden_chars()
        .with_default_blocked_patterns()
        .add_blocked_pattern(r"(?i)\b(php|sh|bash|cmd|powershell)\b") // Block script references
        .expect("Invalid regex pattern")
        .build();

    let username_validator = UsernameValidator;
    let phone_validator = PhoneValidator;
    let command_validator = CommandValidator;
    let text_validator = TextMessageValidator;

    teloxide::repl(bot, move |bot: Bot, msg: Message| {
        let config = config.clone();
        let username_validator = username_validator.clone();
        let phone_validator = phone_validator.clone();
        let command_validator = command_validator.clone();
        let text_validator = text_validator.clone();

        async move {
            if let Some(text) = msg.text() {
                // Обработка команд
                if text.starts_with('/') {
                    match sanitize_and_validate_async(text, &command_validator, &config).await {
                        Ok(sanitized) => {
                            bot.send_message(
                                msg.chat.id,
                                format!("Valid command: {}", sanitized.cleaned),
                            )
                            .await?;
                        }
                        Err(e) => {
                            bot.send_message(msg.chat.id, format!("Invalid command: {}", e))
                                .await?;
                        }
                    }
                }
                // Обработка username
                else if text.starts_with('@') {
                    match sanitize_and_validate_async(&text[1..], &username_validator, &config)
                        .await
                    {
                        Ok(sanitized) => {
                            bot.send_message(
                                msg.chat.id,
                                format!("Valid username: @{}", sanitized.cleaned),
                            )
                            .await?;
                        }
                        Err(e) => {
                            bot.send_message(msg.chat.id, format!("Invalid username: {}", e))
                                .await?;
                        }
                    }
                } else if text.starts_with('+') {
                    match sanitize_and_validate_async(text, &phone_validator, &config).await {
                        Ok(sanitized) => {
                            bot.send_message(
                                msg.chat.id,
                                format!("Valid phone: {}", sanitized.cleaned),
                            )
                            .await?;
                        }
                        Err(e) => {
                            bot.send_message(msg.chat.id, format!("Invalid phone: {}", e))
                                .await?;
                        }
                    }
                } else {
                    match sanitize_and_validate_async(text, &text_validator, &config).await {
                        Ok(sanitized) => {
                            bot.send_message(
                                msg.chat.id,
                                format!("Safe message: {}", sanitized.cleaned),
                            )
                            .await?;
                        }
                        Err(e) => {
                            bot.send_message(
                                msg.chat.id,
                                format!("Dangerous input detected: {}", e),
                            )
                            .await?;
                        }
                    }
                }
            }
            Ok(())
        }
    })
    .await;
}
