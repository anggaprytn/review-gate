use regex::Regex;

pub fn redact_secrets(input: &str) -> String {
    let mut output = input.to_string();

    let patterns = [
        (
            r"(?i)(authorization\s*:\s*bearer\s+)[^\s\\]+",
            "${1}[REDACTED_TOKEN]",
        ),
        (
            r"(?i)(authorization\s*:\s*)[^\n\r]+",
            "${1}[REDACTED_TOKEN]",
        ),
        (r"(?i)(cookie\s*:\s*)[^\n\r]+", "${1}[REDACTED_COOKIE]"),
        (
            r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+",
            "${1}[REDACTED_TOKEN]",
        ),
        (
            r#"(?i)((api[_-]?key|access[_-]?token|secret[_-]?key|token)\s*[:=]\s*["']?)[^"'\s]+"#,
            "${1}[REDACTED_SECRET]",
        ),
        (
            r#"(?i)((password|passwd|pwd)\s*[:=]\s*["']?)[^"'\s]+"#,
            "${1}[REDACTED_PASSWORD]",
        ),
        (
            r"(?i)\b(postgres|postgresql|mysql|mariadb|mongodb|redis)://[^\s]+",
            "[REDACTED_DATABASE_URL]",
        ),
        (
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
            "[REDACTED_PRIVATE_KEY]",
        ),
    ];

    for (pattern, replacement) in patterns {
        let regex = Regex::new(pattern).expect("redaction regex must compile");
        output = regex.replace_all(&output, replacement).to_string();
    }

    output
}

#[cfg(test)]
mod tests {
    use super::redact_secrets;

    #[test]
    fn redacts_common_secret_patterns() {
        let input =
            "Authorization: Bearer abc.def\ndatabase_url=postgres://u:p@db/app\npassword = hunter2";
        let output = redact_secrets(input);

        assert!(output.contains("[REDACTED_TOKEN]"));
        assert!(output.contains("[REDACTED_DATABASE_URL]"));
        assert!(output.contains("[REDACTED_PASSWORD]"));
        assert!(!output.contains("hunter2"));
    }
}
