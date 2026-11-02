//! JSON-lines audit log of every firewall decision.
//!
//! Records describe *what* was decided and *which rule* decided it, never the
//! offending content: redacted secrets and rejected argument values do not
//! appear here.

use std::io::Write;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::Value;

/// Ordered by severity; a response that triggers several rules is recorded
/// with the most severe outcome.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    #[default]
    Allow,
    Alert,
    Filter,
    Annotate,
    Redact,
    Block,
    Deny,
    Drop,
}

#[derive(Debug, Default, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Peer {
    #[default]
    Client,
    Server,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub rule: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct Event<'a> {
    /// Who sent the message being judged.
    pub from: Peer,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<&'a Value>,
    /// Tool name, resource URI or prompt name the request is about.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<&'a str>,
    pub decision: Decision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// For responses: time since the request was forwarded to the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<Finding>,
}

#[derive(Serialize)]
struct Record<'a> {
    ts: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<&'a str>,
    #[serde(flatten)]
    event: Event<'a>,
}

pub struct AuditLog {
    out: Box<dyn Write + Send>,
    server: Option<String>,
}

impl AuditLog {
    pub fn new(out: Box<dyn Write + Send>, server: Option<String>) -> Self {
        Self { out, server }
    }

    pub fn record(&mut self, event: Event<'_>) {
        let record = Record {
            ts: rfc3339(SystemTime::now()),
            server: self.server.as_deref(),
            event,
        };
        // One write per record keeps lines intact when several firewalls
        // append to the same file.
        let result = serde_json::to_vec(&record)
            .map_err(std::io::Error::from)
            .and_then(|mut line| {
                line.push(b'\n');
                self.out.write_all(&line)?;
                self.out.flush()
            });
        if let Err(err) = result {
            tracing::error!("failed to write audit record: {err}");
        }
    }
}

/// Formats a UTC timestamp as RFC 3339 with millisecond precision.
fn rfc3339(time: SystemTime) -> String {
    let since_epoch = time.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let secs = since_epoch.as_secs();
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (year, month, day) = civil_from_days(days as i64);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        since_epoch.subsec_millis()
    )
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's
/// `civil_from_days`), to avoid a date-time dependency for one format.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn formats_timestamps() {
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        let t = UNIX_EPOCH + Duration::from_millis(951_782_400_123); // leap day
        assert_eq!(rfc3339(t), "2000-02-29T00:00:00.123Z");
        let t = UNIX_EPOCH + Duration::from_secs(1_798_761_599);
        assert_eq!(rfc3339(t), "2026-12-31T23:59:59.000Z");
    }

    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn writes_one_json_object_per_line() {
        let sink = Shared::default();
        let mut log = AuditLog::new(Box::new(sink.clone()), Some("fs".into()));
        log.record(Event {
            method: Some("tools/call"),
            target: Some("exec"),
            decision: Decision::Deny,
            rule: Some("tools.deny[\"exec\"]".into()),
            ..Default::default()
        });
        let text = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        assert!(text.ends_with('\n'));
        let record: Value = serde_json::from_str(text.trim_end()).unwrap();
        assert_eq!(record["server"], "fs");
        assert_eq!(record["from"], "client");
        assert_eq!(record["decision"], "deny");
        assert_eq!(record["target"], "exec");
        assert!(record.get("latency_ms").is_none());
    }
}
