//! Per-argument constraints for `tools/call`, addressed by JSON pointer.

use std::path::{Path, PathBuf};

use regex::Regex;
use serde::Deserialize;
use serde_json::Value;

use crate::paths;

/// One `[tool.<name>.args."<pointer>"]` table from the policy file.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ArgRuleConfig {
    pub required: bool,
    pub regex: Option<String>,
    pub one_of: Option<Vec<Value>>,
    pub max_len: Option<usize>,
    pub path_under: Option<Vec<String>>,
}

#[derive(Debug)]
pub struct ArgRule {
    pointer: String,
    required: bool,
    regex: Option<Regex>,
    one_of: Option<Vec<Value>>,
    max_len: Option<usize>,
    roots: Option<Vec<PathBuf>>,
}

/// Why an argument was rejected. Deliberately carries no argument value:
/// it ends up in the audit log and the value could itself be a secret.
#[derive(Debug, PartialEq)]
pub struct Violation {
    pub constraint: &'static str,
    pub detail: String,
}

impl ArgRule {
    pub fn compile(pointer: &str, config: ArgRuleConfig, base_dir: &Path) -> Result<Self, String> {
        if !pointer.is_empty() && !pointer.starts_with('/') {
            return Err(format!(
                "argument pointer {pointer:?} must be empty or start with '/'"
            ));
        }
        // Anchor the pattern so the whole value must match: an unanchored
        // allow-pattern is satisfied by any value that merely contains it.
        let regex = config
            .regex
            .map(|re| {
                Regex::new(&format!("^(?:{re})$"))
                    .map_err(|e| format!("invalid regex for {pointer:?}: {e}"))
            })
            .transpose()?;
        let roots = config
            .path_under
            .map(|roots| {
                roots
                    .iter()
                    .map(|root| {
                        paths::resolve_root(root, base_dir)
                            .map_err(|e| format!("allowed root {root:?} for {pointer:?}: {e}"))
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        Ok(Self {
            pointer: pointer.to_owned(),
            required: config.required,
            regex,
            one_of: config.one_of,
            max_len: config.max_len,
            roots,
        })
    }

    pub fn pointer(&self) -> &str {
        &self.pointer
    }

    /// Checks the argument this rule points at. Absent arguments pass unless
    /// the rule is `required`; arrays are checked element by element.
    pub fn check(&self, arguments: &Value) -> Result<(), Violation> {
        match arguments.pointer(&self.pointer) {
            None if self.required => Err(violation("required", "argument is missing")),
            None => Ok(()),
            Some(Value::Array(items)) => items.iter().try_for_each(|item| self.check_value(item)),
            Some(value) => self.check_value(value),
        }
    }

    fn check_value(&self, value: &Value) -> Result<(), Violation> {
        if let Some(allowed) = &self.one_of
            && !allowed.contains(value)
        {
            return Err(violation(
                "one_of",
                "value is not one of the allowed values",
            ));
        }
        if self.regex.is_none() && self.max_len.is_none() && self.roots.is_none() {
            return Ok(());
        }
        let Some(text) = value.as_str() else {
            return Err(violation("type", "expected a string"));
        };
        if let Some(max) = self.max_len
            && text.chars().count() > max
        {
            return Err(violation(
                "max_len",
                format!("longer than {max} characters"),
            ));
        }
        if let Some(regex) = &self.regex
            && !regex.is_match(text)
        {
            return Err(violation("regex", "does not match the required pattern"));
        }
        if let Some(roots) = &self.roots {
            let resolved = paths::resolve_argument(text).map_err(|e| violation("path_under", e))?;
            if !paths::is_within(&resolved, roots) {
                return Err(violation("path_under", "path is outside the allowed roots"));
            }
        }
        Ok(())
    }
}

fn violation(constraint: &'static str, detail: impl Into<String>) -> Violation {
    Violation {
        constraint,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rule(pointer: &str, toml_src: &str) -> ArgRule {
        let config: ArgRuleConfig = toml::from_str(toml_src).unwrap();
        ArgRule::compile(pointer, config, Path::new(".")).unwrap()
    }

    fn constraint(rule: &ArgRule, args: Value) -> Option<&'static str> {
        rule.check(&args).err().map(|v| v.constraint)
    }

    #[test]
    fn regex_must_match_whole_value() {
        let r = rule("/sql", r#"regex = "SELECT .*""#);
        assert_eq!(constraint(&r, json!({"sql": "SELECT 1"})), None);
        assert_eq!(
            constraint(&r, json!({"sql": "DROP TABLE x; SELECT 1"})),
            Some("regex")
        );
    }

    #[test]
    fn one_of_and_max_len() {
        let r = rule("/mode", r#"one_of = ["fast", "safe"]"#);
        assert_eq!(constraint(&r, json!({"mode": "safe"})), None);
        assert_eq!(constraint(&r, json!({"mode": "yolo"})), Some("one_of"));

        let r = rule("/q", "max_len = 3");
        assert_eq!(constraint(&r, json!({"q": "äöü"})), None);
        assert_eq!(constraint(&r, json!({"q": "abcd"})), Some("max_len"));
        assert_eq!(constraint(&r, json!({"q": 42})), Some("type"));
    }

    #[test]
    fn missing_arguments_and_arrays() {
        let r = rule("/path", "max_len = 5");
        assert_eq!(constraint(&r, json!({})), None);
        let r = rule("/path", "max_len = 5\nrequired = true");
        assert_eq!(constraint(&r, json!({})), Some("required"));

        let r = rule("/paths", "max_len = 5");
        assert_eq!(constraint(&r, json!({"paths": ["a", "b"]})), None);
        assert_eq!(
            constraint(&r, json!({"paths": ["a", "toolong"]})),
            Some("max_len")
        );
    }

    #[test]
    fn nested_pointers() {
        let r = rule("/options/depth", "one_of = [1, 2]");
        assert_eq!(constraint(&r, json!({"options": {"depth": 2}})), None);
        assert_eq!(
            constraint(&r, json!({"options": {"depth": 9}})),
            Some("one_of")
        );
    }

    #[test]
    fn rejects_bad_configuration() {
        let bad_pointer = ArgRule::compile("path", ArgRuleConfig::default(), Path::new("."));
        assert!(bad_pointer.is_err());
        let config = ArgRuleConfig {
            regex: Some("(".into()),
            ..Default::default()
        };
        assert!(ArgRule::compile("/x", config, Path::new(".")).is_err());
    }
}
