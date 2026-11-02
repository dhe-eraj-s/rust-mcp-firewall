//! End-to-end tests: the real `mcp-firewall` binary in front of the
//! `mock_server` example, talking over real stdio pipes.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

const TIMEOUT: Duration = Duration::from_secs(10);

const POLICY: &str = r#"
[tools]
deny = ["exec_*"]
require_confirmation = ["delete_file"]

[tool.read_file.args."/path"]
path_under = ["project"]

[resources]
deny = ["**/.env"]

[prompts]
deny = ["jailbreak"]
"#;

struct Proxy {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: mpsc::Receiver<String>,
    dir: PathBuf,
    next_id: u64,
}

impl Proxy {
    fn start(name: &str, policy: &str, env: &[(&str, &str)]) -> Self {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("proxy-{name}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("project")).unwrap();
        fs::write(dir.join("project/notes.txt"), "hello").unwrap();
        fs::write(dir.join("policy.toml"), policy).unwrap();

        let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-firewall"))
            .args([
                "--config",
                "policy.toml",
                "--audit-log",
                "audit.jsonl",
                "--server-name",
                "mock",
                "--",
            ])
            .arg(mock_server())
            .current_dir(&dir)
            .envs(env.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("failed to start mcp-firewall");

        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            stdin: child.stdin.take(),
            child,
            stdout: rx,
            dir,
            next_id: 0,
        }
    }

    fn send_raw(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().expect("stdin already closed");
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
    }

    fn recv(&self) -> Value {
        let line = self
            .stdout
            .recv_timeout(TIMEOUT)
            .expect("no response from firewall");
        serde_json::from_str(&line).unwrap()
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send_raw(
            &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string(),
        );
        let response = self.recv();
        assert_eq!(
            response["id"], id,
            "response correlated to the wrong request"
        );
        response
    }

    fn call(&mut self, tool: &str, arguments: Value) -> Value {
        self.request("tools/call", json!({"name": tool, "arguments": arguments}))
    }

    fn audit_log(&self) -> String {
        fs::read_to_string(self.dir.join("audit.jsonl")).unwrap_or_default()
    }

    /// Closes the client side and waits for the firewall to exit.
    fn finish(mut self) -> ExitStatus {
        drop(self.stdin.take());
        for _ in 0..100 {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        panic!("firewall did not exit after its stdin closed");
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `cargo test` builds examples next to the binaries, in `<target>/<profile>/examples`.
fn mock_server() -> PathBuf {
    let bin = Path::new(env!("CARGO_BIN_EXE_mcp-firewall"));
    let path = bin
        .parent()
        .unwrap()
        .join("examples")
        .join(format!("mock_server{}", std::env::consts::EXE_SUFFIX));
    assert!(
        path.exists(),
        "{} missing; run `cargo test` (which builds examples)",
        path.display()
    );
    path
}

fn names(list: &Value, field: &str) -> Vec<String> {
    list.as_array()
        .unwrap()
        .iter()
        .map(|item| item[field].as_str().unwrap().to_owned())
        .collect()
}

fn policy_rule(response: &Value) -> &str {
    assert_eq!(
        response["error"]["code"], -32001,
        "expected a policy error: {response}"
    );
    response["error"]["data"]["rule"].as_str().unwrap()
}

fn text(response: &Value) -> String {
    response["result"]["content"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item["text"].as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn denied_tools_resources_and_prompts_are_hidden() {
    let mut proxy = Proxy::start("lists", POLICY, &[]);
    let init = proxy.request("initialize", json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}));
    assert_eq!(init["result"]["serverInfo"]["name"], "mock-server");
    proxy.send_raw(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);

    let tools = proxy.request("tools/list", json!({}));
    let tools = names(&tools["result"]["tools"], "name");
    assert!(tools.contains(&"echo".to_owned()));
    assert!(!tools.contains(&"exec_command".to_owned()));

    let resources = proxy.request("resources/list", json!({}));
    assert_eq!(
        names(&resources["result"]["resources"], "uri"),
        ["file:///project/README.md"]
    );

    let prompts = proxy.request("prompts/list", json!({}));
    assert_eq!(names(&prompts["result"]["prompts"], "name"), ["summarize"]);
}

#[test]
fn denied_calls_get_json_rpc_errors() {
    let mut proxy = Proxy::start("blocked", POLICY, &[]);
    let response = proxy.call("exec_command", json!({"command": "rm -rf /"}));
    assert_eq!(policy_rule(&response), r#"tools.deny["exec_*"]"#);

    let response = proxy.request("resources/read", json!({"uri": "file:///project/.env"}));
    assert_eq!(policy_rule(&response), r#"resources.deny["**/.env"]"#);

    // The session keeps working after a denial.
    assert_eq!(
        text(&proxy.call("echo", json!({"text": "still here"}))),
        "still here"
    );

    let audit = proxy.audit_log();
    assert!(
        audit
            .lines()
            .any(|l| l.contains(r#""decision":"deny""#) && l.contains("exec_command"))
    );
}

#[test]
fn path_arguments_are_confined_to_the_project() {
    let mut proxy = Proxy::start("paths", POLICY, &[]);
    let ok = proxy.call("read_file", json!({"path": "project/notes.txt"}));
    assert_eq!(text(&ok), "contents of project/notes.txt");

    for escape in ["project/../policy.toml", "/etc/passwd", "~/.ssh/id_rsa"] {
        let denied = proxy.call("read_file", json!({"path": escape}));
        assert_eq!(
            policy_rule(&denied),
            r#"tool.read_file.args["/path"].path_under"#,
            "{escape}"
        );
    }
}

#[test]
fn confirmation_flow() {
    let mut proxy = Proxy::start("confirm", POLICY, &[]);
    let denied = proxy.call("delete_file", json!({"path": "project/notes.txt"}));
    assert_eq!(
        policy_rule(&denied),
        r#"tools.require_confirmation["delete_file"]"#
    );
    assert!(
        denied["error"]["message"]
            .as_str()
            .unwrap()
            .contains("mcp-firewall/confirmed")
    );

    let confirmed = proxy.request(
        "tools/call",
        json!({"name": "delete_file", "arguments": {"path": "x"}, "_meta": {"mcp-firewall/confirmed": true}}),
    );
    assert_eq!(text(&confirmed), "deleted x");
}

#[test]
fn secrets_are_redacted_from_results_and_absent_from_the_audit_log() {
    let mut proxy = Proxy::start("secrets", POLICY, &[]);
    let response = proxy.call("leak_secret", json!({}));
    let body = text(&response);
    assert!(
        body.contains("AWS_ACCESS_KEY_ID=[REDACTED:aws_access_key_id]"),
        "{body}"
    );
    assert!(
        body.contains("GITHUB_TOKEN=[REDACTED:github_token]"),
        "{body}"
    );
    assert!(!body.contains("AKIA"));

    let audit = proxy.audit_log();
    assert!(audit.contains("secrets.aws_access_key_id"));
    assert!(!audit.contains("AKIAIOSFODNN7EXAMPLE"));
}

#[test]
fn injected_tool_output_is_annotated_or_blocked() {
    let mut proxy = Proxy::start("inject-annotate", POLICY, &[]);
    let response = proxy.call("fetch_page", json!({"url": "https://docs.example"}));
    let content = response["result"]["content"].as_array().unwrap();
    assert!(
        content[0]["text"]
            .as_str()
            .unwrap()
            .starts_with("[mcp-firewall]")
    );
    assert!(
        content[1]["text"]
            .as_str()
            .unwrap()
            .contains("IGNORE ALL PREVIOUS")
    );

    let policy = format!("{POLICY}\n[injection]\naction = \"block\"\n");
    let mut proxy = Proxy::start("inject-block", &policy, &[]);
    let response = proxy.call("fetch_page", json!({"url": "https://docs.example"}));
    assert_eq!(policy_rule(&response), "injection");
}

#[test]
fn rug_pull_hides_and_blocks_the_changed_tool() {
    let mut proxy = Proxy::start("rugpull", POLICY, &[("MOCK_RUG_PULL", "1")]);
    let first = proxy.request("tools/list", json!({}));
    assert!(names(&first["result"]["tools"], "name").contains(&"echo".to_owned()));

    let second = proxy.request("tools/list", json!({}));
    let tools = names(&second["result"]["tools"], "name");
    assert!(!tools.contains(&"echo".to_owned()));
    assert!(
        tools.contains(&"read_file".to_owned()),
        "unchanged tools stay visible"
    );

    assert_eq!(
        policy_rule(&proxy.call("echo", json!({"text": "hi"}))),
        "rug_pull"
    );
    assert!(proxy.audit_log().contains(r#""rule":"rug_pull""#));
}

#[test]
fn malformed_input_and_string_ids() {
    let mut proxy = Proxy::start("framing", POLICY, &[]);
    proxy.send_raw("this is not json");
    assert_eq!(proxy.recv()["error"]["code"], -32700);

    proxy.send_raw(r#"{"jsonrpc":"2.0","id":"req-a","method":"ping"}"#);
    let pong = proxy.recv();
    assert_eq!(pong["id"], "req-a");
    assert_eq!(pong["result"], json!({}));
}

#[test]
fn exit_status_of_the_server_is_propagated() {
    let mut proxy = Proxy::start("exit", POLICY, &[("MOCK_EXIT_CODE", "3")]);
    proxy.request("ping", json!({}));
    assert_eq!(proxy.finish().code(), Some(3));
}
