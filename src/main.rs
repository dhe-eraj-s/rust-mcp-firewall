use std::error::Error;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use clap::Parser;
use tracing_subscriber::filter::LevelFilter;

use mcp_firewall::audit::AuditLog;
use mcp_firewall::firewall::Firewall;
use mcp_firewall::policy::Policy;
use mcp_firewall::proxy;

/// A policy-enforcing stdio proxy for Model Context Protocol servers.
///
/// Configure your MCP client to launch `mcp-firewall --config policy.toml --
/// <server command>` instead of the server itself.
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// Policy file (TOML).
    #[arg(short, long, value_name = "FILE")]
    config: PathBuf,

    /// Append audit records (JSON lines) to this file instead of stderr.
    #[arg(long, value_name = "FILE")]
    audit_log: Option<PathBuf>,

    /// Name stored in every audit record, to tell servers apart in a shared log.
    #[arg(long, value_name = "NAME")]
    server_name: Option<String>,

    /// Largest accepted message in bytes; longer lines are discarded.
    #[arg(long, value_name = "BYTES", default_value_t = 16 * 1024 * 1024)]
    max_message_bytes: usize,

    /// Diagnostic log level on stderr: off, error, warn, info, debug, trace.
    #[arg(long, value_name = "LEVEL", default_value = "warn")]
    log_level: LevelFilter,

    /// Validate the policy file and exit.
    #[arg(long)]
    check: bool,

    /// The MCP server command and its arguments.
    #[arg(last = true, value_name = "COMMAND", required_unless_present = "check")]
    command: Vec<OsString>,
}

fn main() {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_max_level(cli.log_level)
        .with_target(false)
        .with_ansi(io::stderr().is_terminal())
        .init();

    let code = match run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("mcp-firewall: {err}");
            1
        }
    };
    std::process::exit(code);
}

fn run(cli: Cli) -> Result<i32, Box<dyn Error>> {
    let policy = Policy::load(&cli.config)?;
    if cli.check {
        println!("{}: OK", cli.config.display());
        return Ok(0);
    }

    let sink: Box<dyn Write + Send> = match &cli.audit_log {
        Some(path) => Box::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| format!("cannot open audit log {}: {e}", path.display()))?,
        ),
        None => Box::new(io::stderr()),
    };
    let firewall = Firewall::new(policy, AuditLog::new(sink, cli.server_name));

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(proxy::run(firewall, &cli.command, cli.max_message_bytes));
    // Tokio reads stdin with a blocking call that cannot be cancelled; a
    // normal runtime drop would wait for the client to send another line.
    runtime.shutdown_background();
    Ok(result?)
}
