//! A policy-enforcing proxy for Model Context Protocol (MCP) servers.
//!
//! The firewall sits on the stdio pipe between an MCP client and a server,
//! inspects every JSON-RPC message in both directions and applies a TOML
//! policy: tool/resource/prompt allow and deny lists, argument constraints,
//! rate limits, secret redaction, prompt-injection heuristics and detection of
//! tool definitions that change mid-session.
//!
//! [`firewall::Firewall`] holds all decision logic and is synchronous and
//! IO-free; [`proxy`] wires it to the client and the child process.

pub mod args;
pub mod audit;
pub mod firewall;
pub mod framing;
pub mod jsonrpc;
pub mod paths;
pub mod policy;
pub mod proxy;
pub mod ratelimit;
pub mod rugpull;
pub mod scan;
