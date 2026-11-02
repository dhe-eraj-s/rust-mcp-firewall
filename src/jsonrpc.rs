//! Just enough JSON-RPC 2.0 to route MCP messages.
//!
//! Messages stay as [`serde_json::Value`] so fields the firewall does not know
//! about are forwarded untouched.

use serde_json::{Value, json};

pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
/// Implementation-defined server error used for every policy rejection, so
/// clients can tell firewall denials apart from upstream failures.
pub const POLICY_VIOLATION: i64 = -32001;

/// The shape of a JSON-RPC message, borrowed from the parsed value.
#[derive(Debug, PartialEq)]
pub enum Kind<'a> {
    Request { id: &'a Value, method: &'a str },
    Notification { method: &'a str },
    Response { id: &'a Value },
    Invalid,
}

pub fn classify(msg: &Value) -> Kind<'_> {
    let Some(obj) = msg.as_object() else {
        return Kind::Invalid;
    };
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Kind::Invalid;
    }
    let method = obj.get("method").and_then(Value::as_str);
    let id = obj.get("id").filter(|id| id.is_string() || id.is_number());
    let is_reply = obj.contains_key("result") || obj.contains_key("error");
    match (method, id) {
        (Some(method), Some(id)) => Kind::Request { id, method },
        (Some(method), None) if !obj.contains_key("id") => Kind::Notification { method },
        (None, Some(id)) if is_reply => Kind::Response { id },
        _ => Kind::Invalid,
    }
}

/// Key for correlating responses with requests. Serialising keeps `1` and
/// `"1"` distinct, as JSON-RPC requires.
pub fn id_key(id: &Value) -> String {
    id.to_string()
}

pub fn error_response(id: &Value, code: i64, message: &str, data: Option<Value>) -> Value {
    let mut error = json!({ "code": code, "message": message });
    if let Some(data) = data {
        error["data"] = data;
    }
    json!({ "jsonrpc": "2.0", "id": id, "error": error })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_message_shapes() {
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});
        assert_eq!(
            classify(&req),
            Kind::Request {
                id: &json!(1),
                method: "ping"
            }
        );
        let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        assert_eq!(
            classify(&note),
            Kind::Notification {
                method: "notifications/initialized"
            }
        );
        let resp = json!({"jsonrpc": "2.0", "id": "a", "result": {}});
        assert_eq!(classify(&resp), Kind::Response { id: &json!("a") });
    }

    #[test]
    fn rejects_malformed_messages() {
        for bad in [
            json!([{"jsonrpc": "2.0", "id": 1, "method": "ping"}]),
            json!({"id": 1, "method": "ping"}),
            json!({"jsonrpc": "2.0", "id": null, "method": "ping"}),
            json!({"jsonrpc": "2.0", "id": 1}),
            json!({"jsonrpc": "2.0", "id": {"x": 1}, "result": {}}),
        ] {
            assert_eq!(classify(&bad), Kind::Invalid, "{bad}");
        }
    }

    #[test]
    fn numeric_and_string_ids_do_not_collide() {
        assert_ne!(id_key(&json!(1)), id_key(&json!("1")));
    }
}
