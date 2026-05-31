use regex::Regex;

pub fn redact_secrets(input: &str) -> String {
    let mut output = input.to_string();

    let patterns = [
        (
            r"(?m)^[+\- ]?-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?^[+\- ]?-----END [A-Z ]*PRIVATE KEY-----",
            "[REDACTED_PRIVATE_KEY]",
        ),
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

    #[test]
    fn redacts_diff_prefixed_multiline_private_keys() {
        let input = "+-----BEGIN PRIVATE KEY-----\n+abc123\n+def456\n+-----END PRIVATE KEY-----";
        let output = redact_secrets(input);

        assert_eq!(output, "[REDACTED_PRIVATE_KEY]");
        assert!(!output.contains("abc123"));
    }

    #[test]
    fn redacts_authorization_headers_and_env_style_keys() {
        let input = "Authorization: Basic abc123\nAPI_KEY=sk_live_secret\nDB_PASSWORD=\"hunter2\"";
        let output = redact_secrets(input);

        assert!(output.contains("Authorization: [REDACTED_TOKEN]"));
        assert!(output.contains("API_KEY=[REDACTED_SECRET]"));
        assert!(output.contains("DB_PASSWORD=\"[REDACTED_PASSWORD]\""));
        assert!(!output.contains("sk_live_secret"));
        assert!(!output.contains("hunter2"));
    }
}
