//! Content scanners applied to server responses.

pub mod injection;
pub mod secrets;

use serde::Deserialize;
use serde_json::Value;

/// A user-supplied named pattern (`[[secrets.custom]]`,
/// `[[injection.extra_patterns]]`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedPattern {
    pub name: String,
    pub regex: String,
}

/// A byte range of a string and the rule that matched it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match<'r> {
    pub start: usize,
    pub end: usize,
    pub rule: &'r str,
}

/// Replaces each match with `[<marker>:<rule>]`. Overlapping matches are
/// merged so no fragment of a secret survives between two replacements.
pub fn replace_matches(text: &str, mut matches: Vec<Match<'_>>, marker: &str) -> String {
    matches.sort_by_key(|m| (m.start, std::cmp::Reverse(m.end)));
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    let mut iter = matches.into_iter().peekable();
    while let Some(mut current) = iter.next() {
        while let Some(next) = iter.next_if(|next| next.start < current.end) {
            current.end = current.end.max(next.end);
        }
        let start = current.start.max(cursor);
        out.push_str(&text[cursor..start]);
        out.push_str(&format!("[{marker}:{}]", current.rule));
        cursor = current.end.max(cursor);
    }
    out.push_str(&text[cursor..]);
    out
}

/// Calls `f` on every string inside `value` that a model could read.
/// Base64 payloads (`blob`, and `data` of image/audio content) are skipped:
/// they are high-entropy by nature and would drown the entropy detector.
pub fn for_each_text(value: &mut Value, f: &mut impl FnMut(&mut String)) {
    match value {
        Value::String(text) => f(text),
        Value::Array(items) => items.iter_mut().for_each(|item| for_each_text(item, f)),
        Value::Object(map) => {
            let binary = matches!(
                map.get("type").and_then(Value::as_str),
                Some("image" | "audio")
            );
            for (key, item) in map.iter_mut() {
                if key == "blob" || (binary && key == "data") {
                    continue;
                }
                for_each_text(item, f);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn m(start: usize, end: usize, rule: &str) -> Match<'_> {
        Match { start, end, rule }
    }

    #[test]
    fn replaces_and_merges_overlaps() {
        let text = "a SECRET and TOKEN here";
        let out = replace_matches(text, vec![m(13, 18, "t"), m(2, 8, "s"), m(4, 10, "x")], "R");
        assert_eq!(out, "a [R:s]nd [R:t] here");
    }

    #[test]
    fn walks_text_but_skips_binary_payloads() {
        let mut v = json!({
            "content": [
                {"type": "text", "text": "hello"},
                {"type": "image", "data": "aW1hZ2U=", "mimeType": "image/png"},
                {"type": "resource", "resource": {"uri": "file:///a", "blob": "YmxvYg=="}}
            ]
        });
        let mut seen = Vec::new();
        for_each_text(&mut v, &mut |s| seen.push(s.clone()));
        assert!(seen.contains(&"hello".to_string()));
        assert!(!seen.iter().any(|s| s == "aW1hZ2U=" || s == "YmxvYg=="));
    }
}
