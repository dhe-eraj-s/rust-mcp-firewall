//! Secret detection: well-known credential formats plus a Shannon-entropy
//! check for unknown token formats.

use regex::Regex;
use serde::Deserialize;

use super::{Match, NamedPattern};

/// Built-in detectors. When a pattern has a capture group, only the group is
/// redacted, so labels such as `aws_secret_access_key=` stay readable.
const BUILTIN: &[(&str, &str)] = &[
    (
        "aws_access_key_id",
        r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
    ),
    (
        "aws_secret_access_key",
        r#"(?i)aws_?secret_?access_?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})"#,
    ),
    (
        "github_token",
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b",
    ),
    (
        "github_fine_grained_token",
        r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b",
    ),
    ("slack_token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    (
        "private_key",
        r"(?s)-----BEGIN[A-Z ]*PRIVATE KEY-----.*?(?:-----END[A-Z ]*PRIVATE KEY-----|\z)",
    ),
    (
        "jwt",
        r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
    ),
];

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecretsConfig {
    pub enabled: bool,
    pub entropy: bool,
    /// Minimum Shannon entropy in bits per character.
    pub entropy_threshold: f64,
    /// Minimum token length for the entropy check.
    pub entropy_min_len: usize,
    pub custom: Vec<NamedPattern>,
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            entropy: true,
            entropy_threshold: 4.5,
            entropy_min_len: 32,
            custom: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct SecretScanner {
    detectors: Vec<(String, Regex)>,
    entropy: Option<(Regex, f64)>,
}

const ENTROPY_RULE: &str = "high_entropy";

impl SecretScanner {
    pub fn new(config: SecretsConfig) -> Result<Self, String> {
        if !config.enabled {
            return Ok(Self {
                detectors: Vec::new(),
                entropy: None,
            });
        }
        let builtin = BUILTIN
            .iter()
            .map(|&(name, re)| (name.to_owned(), re.to_owned()));
        let custom = config.custom.into_iter().map(|p| (p.name, p.regex));
        let detectors = builtin
            .chain(custom)
            .map(|(name, re)| {
                Regex::new(&re)
                    .map(|re| (name.clone(), re))
                    .map_err(|e| format!("invalid secret pattern {name:?}: {e}"))
            })
            .collect::<Result<_, _>>()?;
        let entropy = config.entropy.then(|| {
            // The base64 / base64url alphabet, with `=` only as trailing
            // padding so `NAME=value` pairs split at the `=`.
            let token = Regex::new(&format!(
                "[A-Za-z0-9+/_-]{{{},}}={{0,2}}",
                config.entropy_min_len
            ))
            .expect("token pattern is valid");
            (token, config.entropy_threshold)
        });
        Ok(Self { detectors, entropy })
    }

    pub fn find(&self, text: &str) -> Vec<Match<'_>> {
        let mut found = Vec::new();
        for (name, regex) in &self.detectors {
            for caps in regex.captures_iter(text) {
                let span = caps
                    .get(1)
                    .or_else(|| caps.get(0))
                    .expect("group 0 always matches");
                found.push(Match {
                    start: span.start(),
                    end: span.end(),
                    rule: name,
                });
            }
        }
        if let Some((token, threshold)) = &self.entropy {
            // Skip tokens a specific detector already labelled: its name is
            // more useful in the redaction marker than "high_entropy".
            let random: Vec<_> = token
                .find_iter(text)
                .filter(|t| !found.iter().any(|m| t.start() < m.end && m.start < t.end()))
                .filter(|t| looks_random(t.as_str(), *threshold))
                .map(|t| Match {
                    start: t.start(),
                    end: t.end(),
                    rule: ENTROPY_RULE,
                })
                .collect();
            found.extend(random);
        }
        found
    }
}

/// Random tokens mix upper case, lower case and digits; requiring all three
/// keeps long words, paths and hex digests (git SHAs, UUIDs) from tripping
/// the entropy check.
fn looks_random(token: &str, threshold: f64) -> bool {
    let has = |pred: fn(&u8) -> bool| token.as_bytes().iter().any(pred);
    has(u8::is_ascii_uppercase)
        && has(u8::is_ascii_lowercase)
        && has(u8::is_ascii_digit)
        && shannon_entropy(token) >= threshold
}

pub fn shannon_entropy(text: &str) -> f64 {
    let mut counts = [0usize; 256];
    for byte in text.bytes() {
        counts[usize::from(byte)] += 1;
    }
    let len = text.len() as f64;
    counts
        .iter()
        .filter(|&&n| n > 0)
        .map(|&n| {
            let p = n as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // Fixtures are assembled at runtime so repository secret scanners do not
    // flag this file.
    pub fn fake_github_token() -> String {
        format!("gh{}_{}", "p", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8")
    }

    pub fn fake_private_key() -> String {
        let kind = "RSA PRIVATE KEY";
        format!("-----BEGIN {kind}-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn\n-----END {kind}-----")
    }

    fn scanner() -> SecretScanner {
        SecretScanner::new(SecretsConfig::default()).unwrap()
    }

    fn rules(text: &str) -> Vec<String> {
        let mut rules: Vec<String> = scanner()
            .find(text)
            .iter()
            .map(|m| m.rule.to_owned())
            .collect();
        rules.sort();
        rules.dedup();
        rules
    }

    #[test]
    fn detects_known_credential_formats() {
        assert_eq!(
            rules("key AKIAIOSFODNN7EXAMPLE in config"),
            ["aws_access_key_id"]
        );
        assert_eq!(
            rules(&format!("token={}", fake_github_token())),
            ["github_token"]
        );
        assert!(rules(&format!("x {} y", fake_private_key())).contains(&"private_key".to_string()));
        let jwt = format!(
            "{}.{}.{}",
            "eyJhbGciOiJIUzI1NiJ9",
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
            "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        );
        assert!(rules(&format!("Bearer {jwt}")).contains(&"jwt".to_string()));
        let slack = format!("xox{}-{}", "b", "1234567890-abcdefghij");
        assert_eq!(rules(&slack), ["slack_token"]);
    }

    #[test]
    fn capture_group_redacts_only_the_value() {
        let text = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let scanner = scanner();
        let found = scanner.find(text);
        let m = found
            .iter()
            .find(|m| m.rule == "aws_secret_access_key")
            .unwrap();
        assert_eq!(
            &text[m.start..m.end],
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
    }

    #[test]
    fn truncated_private_key_is_still_caught() {
        let key = fake_private_key();
        let truncated = &key[..key.len() - 20];
        let scanner = scanner();
        let found = scanner.find(truncated);
        assert!(
            found
                .iter()
                .any(|m| m.rule == "private_key" && m.end == truncated.len())
        );
    }

    #[test]
    fn entropy_catches_unknown_random_tokens() {
        assert_eq!(
            rules("api_key: Zx8qT2vLm9WcR4yHn7Bp3KsD6fGj1Ua5Ve0Xo"),
            [ENTROPY_RULE]
        );
    }

    #[test]
    fn common_text_is_not_flagged() {
        for text in [
            "The quick brown fox jumps over the lazy dog.",
            "commit 0123456789abcdef0123456789abcdef01234567",
            "request id 550e8400-e29b-41d4-a716-446655440000",
            "/usr/local/lib/python3.11/site-packages/numpy/core",
            "/home/user/projects/MyApp2/src/components/Button.tsx",
            "ThisIsAVeryLongCamelCaseIdentifierName2024",
            "AKIA is the prefix of AWS access key ids",
            "ghp_short",
        ] {
            assert!(
                rules(text).is_empty(),
                "false positive on {text:?}: {:?}",
                rules(text)
            );
        }
    }

    #[test]
    fn custom_patterns_and_disabling() {
        let config = SecretsConfig {
            custom: vec![NamedPattern {
                name: "internal".into(),
                regex: r"\bACME-[0-9]{6}\b".into(),
            }],
            ..Default::default()
        };
        let scanner = SecretScanner::new(config).unwrap();
        assert_eq!(scanner.find("id ACME-123456")[0].rule, "internal");

        let off = SecretsConfig {
            enabled: false,
            ..Default::default()
        };
        assert!(
            SecretScanner::new(off)
                .unwrap()
                .find("AKIAIOSFODNN7EXAMPLE")
                .is_empty()
        );
    }

    #[test]
    fn entropy_is_bits_per_character() {
        assert_eq!(shannon_entropy("aaaa"), 0.0);
        assert!((shannon_entropy("abcd") - 2.0).abs() < 1e-9);
    }
}
