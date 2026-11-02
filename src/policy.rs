//! The TOML policy file and its compiled, query-ready form.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::path::Path;

use globset::{Glob, GlobBuilder, GlobSet, GlobSetBuilder};
use serde::Deserialize;
use serde_json::Value;

use crate::args::{ArgRule, ArgRuleConfig};
use crate::ratelimit::RateLimit;
use crate::rugpull::{RugPullAction, RugPullConfig};
use crate::scan::injection::{InjectionConfig, InjectionScanner};
use crate::scan::secrets::{SecretScanner, SecretsConfig};

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PolicyFile {
    tools: ToolLists,
    resources: Lists,
    prompts: Lists,
    tool: BTreeMap<String, ToolConfig>,
    secrets: SecretsConfig,
    injection: InjectionConfig,
    rug_pull: RugPullConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Lists {
    allow: Vec<String>,
    deny: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ToolLists {
    allow: Vec<String>,
    deny: Vec<String>,
    require_confirmation: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ToolConfig {
    rate_limit: Option<RateLimit>,
    args: BTreeMap<String, ArgRuleConfig>,
}

#[derive(Debug)]
pub struct ConfigError(String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

/// Why a request was refused: the rule that fired and a message that is
/// safe to show to the model and to write to the audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    pub rule: String,
    pub reason: String,
}

impl Denial {
    pub fn new(rule: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            rule: rule.into(),
            reason: reason.into(),
        }
    }
}

#[derive(Debug)]
struct Patterns {
    globs: Vec<String>,
    set: GlobSet,
}

impl Patterns {
    fn compile(section: &str, globs: Vec<String>) -> Result<Self, ConfigError> {
        let mut builder = GlobSetBuilder::new();
        for glob in &globs {
            builder.add(
                parse_glob(glob).map_err(|e| {
                    ConfigError(format!("{section}: invalid pattern {glob:?}: {e}"))
                })?,
            );
        }
        let set = builder
            .build()
            .map_err(|e| ConfigError(format!("{section}: {e}")))?;
        Ok(Self { globs, set })
    }

    fn first_match(&self, name: &str) -> Option<&str> {
        self.set
            .matches(name)
            .first()
            .map(|&i| self.globs[i].as_str())
    }
}

/// `*` stops at `/` so URI patterns behave like paths (`**` crosses them).
fn parse_glob(glob: &str) -> Result<Glob, globset::Error> {
    GlobBuilder::new(glob).literal_separator(true).build()
}

/// Allow/deny lists for one kind of MCP primitive. Deny always wins; an
/// empty allow list means "everything not denied".
#[derive(Debug)]
struct AccessList {
    section: &'static str,
    noun: &'static str,
    allow: Patterns,
    deny: Patterns,
}

impl AccessList {
    fn compile(
        section: &'static str,
        noun: &'static str,
        allow: Vec<String>,
        deny: Vec<String>,
    ) -> Result<Self, ConfigError> {
        Ok(Self {
            section,
            noun,
            allow: Patterns::compile(section, allow)?,
            deny: Patterns::compile(section, deny)?,
        })
    }

    fn check(&self, name: &str) -> Result<(), Denial> {
        let (section, noun) = (self.section, self.noun);
        if let Some(glob) = self.deny.first_match(name) {
            return Err(Denial::new(
                format!("{section}.deny[{glob:?}]"),
                format!("{noun} '{name}' is denied by policy"),
            ));
        }
        if !self.allow.globs.is_empty() && self.allow.first_match(name).is_none() {
            return Err(Denial::new(
                format!("{section}.allow"),
                format!("{noun} '{name}' is not on the allow list"),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
struct ToolRule {
    rate_limit: Option<RateLimit>,
    args: Vec<ArgRule>,
}

#[derive(Debug)]
pub struct Policy {
    tools: AccessList,
    confirm: Patterns,
    resources: AccessList,
    prompts: AccessList,
    tool_rules: HashMap<String, ToolRule>,
    pub secrets: SecretScanner,
    pub injection: InjectionScanner,
    pub rug_pull: RugPullAction,
}

impl Policy {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError(format!("cannot read policy {}: {e}", path.display())))?;
        let base_dir = path.parent().unwrap_or(Path::new("."));
        Self::from_toml(&text, base_dir)
            .map_err(|e| ConfigError(format!("{}: {e}", path.display())))
    }

    /// Parses a policy. Relative `path_under` roots resolve against `base_dir`.
    pub fn from_toml(text: &str, base_dir: &Path) -> Result<Self, ConfigError> {
        let file: PolicyFile = toml::from_str(text).map_err(|e| ConfigError(e.to_string()))?;

        let mut tool_rules = HashMap::new();
        for (name, config) in file.tool {
            if let Some(limit) = config.rate_limit
                && (limit.calls == 0 || limit.per_secs == 0)
            {
                return Err(ConfigError(format!(
                    "tool.{name}.rate_limit: calls and per_secs must be positive"
                )));
            }
            let args = config
                .args
                .into_iter()
                .map(|(pointer, rule)| ArgRule::compile(&pointer, rule, base_dir))
                .collect::<Result<_, _>>()
                .map_err(|e| ConfigError(format!("tool.{name}.args: {e}")))?;
            tool_rules.insert(
                name,
                ToolRule {
                    rate_limit: config.rate_limit,
                    args,
                },
            );
        }

        Ok(Self {
            tools: AccessList::compile("tools", "tool", file.tools.allow, file.tools.deny)?,
            confirm: Patterns::compile(
                "tools.require_confirmation",
                file.tools.require_confirmation,
            )?,
            resources: AccessList::compile(
                "resources",
                "resource",
                file.resources.allow,
                file.resources.deny,
            )?,
            prompts: AccessList::compile(
                "prompts",
                "prompt",
                file.prompts.allow,
                file.prompts.deny,
            )?,
            tool_rules,
            secrets: SecretScanner::new(file.secrets).map_err(ConfigError)?,
            injection: InjectionScanner::new(file.injection).map_err(ConfigError)?,
            rug_pull: file.rug_pull.action,
        })
    }

    pub fn check_tool(&self, name: &str) -> Result<(), Denial> {
        self.tools.check(name)
    }

    pub fn check_prompt(&self, name: &str) -> Result<(), Denial> {
        self.prompts.check(name)
    }

    pub fn check_resource(&self, uri: &str) -> Result<(), Denial> {
        // Globs compare text, so `file:///allowed/../etc/passwd` would match
        // `file:///allowed/**`. Dot segments are refused outright instead of
        // guessing how the server will normalise them.
        let lower = uri.to_ascii_lowercase();
        if uri.split(['/', '\\']).any(|seg| seg == "." || seg == "..") || lower.contains("%2e") {
            return Err(Denial::new(
                "resources.dot_segments",
                format!("resource URI '{uri}' contains dot segments"),
            ));
        }
        self.resources.check(uri)
    }

    /// The `require_confirmation` pattern covering this tool, if any.
    pub fn confirmation_rule(&self, name: &str) -> Option<&str> {
        self.confirm.first_match(name)
    }

    pub fn check_tool_args(&self, name: &str, arguments: &Value) -> Result<(), Denial> {
        let Some(rule) = self.tool_rules.get(name) else {
            return Ok(());
        };
        for arg in &rule.args {
            arg.check(arguments).map_err(|v| {
                Denial::new(
                    format!("tool.{name}.args[{:?}].{}", arg.pointer(), v.constraint),
                    format!(
                        "argument '{}' of tool '{name}' rejected: {}",
                        arg.pointer(),
                        v.detail
                    ),
                )
            })?;
        }
        Ok(())
    }

    pub fn rate_limit(&self, name: &str) -> Option<RateLimit> {
        self.tool_rules.get(name).and_then(|rule| rule.rate_limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn policy(text: &str) -> Policy {
        Policy::from_toml(text, Path::new(".")).unwrap()
    }

    #[test]
    fn empty_policy_allows_everything() {
        let p = policy("");
        assert!(p.check_tool("anything").is_ok());
        assert!(p.check_resource("file:///etc/hosts").is_ok());
        assert!(p.check_prompt("x").is_ok());
    }

    #[test]
    fn deny_wins_over_allow() {
        let p = policy(
            r#"
            [tools]
            allow = ["read_*", "list_*"]
            deny = ["read_secret*"]
            "#,
        );
        assert!(p.check_tool("read_file").is_ok());
        assert_eq!(
            p.check_tool("read_secrets").unwrap_err().rule,
            r#"tools.deny["read_secret*"]"#
        );
        assert_eq!(p.check_tool("exec").unwrap_err().rule, "tools.allow");
    }

    #[test]
    fn resource_globs_respect_path_separators() {
        let p = policy(
            r#"
            [resources]
            allow = ["file:///srv/app/*", "file:///srv/docs/**"]
            deny = ["**/.env"]
            "#,
        );
        assert!(p.check_resource("file:///srv/app/README.md").is_ok());
        assert!(p.check_resource("file:///srv/app/sub/file").is_err());
        assert!(p.check_resource("file:///srv/docs/a/b/c.md").is_ok());
        assert!(p.check_resource("file:///srv/docs/a/.env").is_err());
    }

    #[test]
    fn resource_dot_segments_are_refused() {
        let p = policy(r#"resources.allow = ["file:///srv/app/**"]"#);
        for uri in [
            "file:///srv/app/../../etc/passwd",
            "file:///srv/app/%2e%2e/etc/passwd",
            "file:///srv/app/%2E%2E/etc/passwd",
            "file:///srv/app/./x",
        ] {
            assert_eq!(
                p.check_resource(uri).unwrap_err().rule,
                "resources.dot_segments",
                "{uri}"
            );
        }
    }

    #[test]
    fn confirmation_and_rate_limits() {
        let p = policy(
            r#"
            tools.require_confirmation = ["delete_*"]
            [tool.search]
            rate_limit = { calls = 5, per_secs = 60 }
            "#,
        );
        assert_eq!(p.confirmation_rule("delete_file"), Some("delete_*"));
        assert_eq!(p.confirmation_rule("read_file"), None);
        assert_eq!(p.rate_limit("search").map(|l| l.calls), Some(5));
        assert!(p.rate_limit("other").is_none());
    }

    #[test]
    fn argument_rules_produce_specific_rule_ids() {
        let p = policy(
            r#"
            [tool.query.args."/sql"]
            regex = "SELECT .*"
            "#,
        );
        assert!(
            p.check_tool_args("query", &json!({"sql": "SELECT 1"}))
                .is_ok()
        );
        let denial = p
            .check_tool_args("query", &json!({"sql": "DELETE FROM t"}))
            .unwrap_err();
        assert_eq!(denial.rule, r#"tool.query.args["/sql"].regex"#);
        assert!(
            !denial.reason.contains("DELETE"),
            "values must not leak into reasons"
        );
    }

    #[test]
    fn invalid_configuration_is_rejected() {
        for bad in [
            "unknown_section = 1",
            "[tools]\nallw = [\"x\"]",
            "[tools]\ndeny = [\"[\"]",
            "[tool.x]\nrate_limit = { calls = 0, per_secs = 1 }",
            "[tool.x.args.\"/p\"]\npath_under = [\"/definitely/not/a/real/dir\"]",
            "[injection]\naction = \"explode\"",
        ] {
            assert!(Policy::from_toml(bad, Path::new(".")).is_err(), "{bad}");
        }
    }

    #[test]
    fn example_policy_parses() {
        let text = include_str!("../examples/policy.toml");
        // The example restricts a project directory that will not exist here,
        // so point it at a directory that does.
        let text = text.replace("~/projects/demo", ".");
        Policy::from_toml(&text, Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    }
}
