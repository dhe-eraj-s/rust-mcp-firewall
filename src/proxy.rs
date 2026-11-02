//! The stdio plumbing: spawns the server, pumps messages through the
//! [`Firewall`] in both directions and manages the child's lifecycle.
//!
//! ```text
//! client stdin ──► pump_client ──► server stdin
//!                       │ (denials)
//!                       ▼
//! client stdout ◄── write_client ◄── pump_server ◄── server stdout
//! ```
//!
//! Both pumps feed one writer task through a bounded channel, so the client
//! never sees interleaved lines. Backpressure is end to end: a pump only
//! reads its next message once the previous one has been written or queued.

use std::ffi::OsString;
use std::future::Future;
use std::io;
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::audit::Peer;
use crate::firewall::{ClientAction, Firewall, ServerAction};
use crate::framing::{Frame, read_frame};

/// How long the server gets to exit after its stdin closes, and again after
/// SIGTERM, before it is killed.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
const CLIENT_QUEUE_DEPTH: usize = 64;

type Shared = Arc<Mutex<Firewall>>;

/// Runs the proxy until the server exits and returns the exit code the
/// firewall should exit with.
pub async fn run(
    firewall: Firewall,
    command: &[OsString],
    max_message_bytes: usize,
) -> io::Result<i32> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no server command given"))?;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("cannot start {}: {e}", program.to_string_lossy()),
            )
        })?;
    let server_in = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("server stdin unavailable"))?;
    let server_out = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("server stdout unavailable"))?;
    let signal = termination_signal()?;

    let firewall = Arc::new(Mutex::new(firewall));
    let (to_client, client_queue) = mpsc::channel(CLIENT_QUEUE_DEPTH);
    let writer = tokio::spawn(write_client(client_queue, tokio::io::stdout()));
    let mut upstream = tokio::spawn(pump_client(
        BufReader::new(tokio::io::stdin()),
        server_in,
        firewall.clone(),
        to_client.clone(),
        max_message_bytes,
    ));
    let mut downstream = tokio::spawn(pump_server(
        BufReader::new(server_out),
        firewall,
        to_client,
        max_message_bytes,
    ));

    let status = tokio::select! {
        status = child.wait() => status?,
        result = &mut upstream => {
            log_task_end("client", result);
            shutdown(&mut child).await?
        }
        () = signal => {
            debug!("termination signal received");
            upstream.abort();
            shutdown(&mut child).await?
        }
    };
    debug!(%status, "server exited");
    upstream.abort();

    // Deliver whatever the server wrote before exiting. A grandchild that
    // inherited its stdout could keep the pipe open, so do not wait forever.
    match timeout(SHUTDOWN_GRACE, &mut downstream).await {
        Ok(result) => log_task_end("server", result),
        Err(_) => downstream.abort(),
    }
    if timeout(SHUTDOWN_GRACE, writer).await.is_err() {
        warn!("client stopped reading; some output may be lost");
    }
    Ok(exit_code(status))
}

async fn pump_client<R>(
    mut input: R,
    mut server: ChildStdin,
    firewall: Shared,
    to_client: mpsc::Sender<Vec<u8>>,
    max_len: usize,
) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
{
    while let Some(frame) = read_frame(&mut input, max_len).await? {
        let action = match frame {
            Frame::Line(line) if is_blank(&line) => continue,
            Frame::Line(line) => match lock(&firewall)?.on_client_message(&line) {
                ClientAction::Forward => Ok(line),
                ClientAction::Reply(reply) => Err(reply),
            },
            Frame::TooLong => match lock(&firewall)?.on_oversized(Peer::Client) {
                Some(reply) => Err(reply),
                None => continue,
            },
        };
        match action {
            Ok(mut line) => {
                line.push(b'\n');
                server.write_all(&line).await?;
                server.flush().await?;
            }
            Err(reply) => {
                if to_client.send(serde_json::to_vec(&reply)?).await.is_err() {
                    break;
                }
            }
        }
    }
    // Dropping `server` closes the child's stdin: the first step of the MCP
    // stdio shutdown sequence.
    Ok(())
}

async fn pump_server<R>(
    mut output: R,
    firewall: Shared,
    to_client: mpsc::Sender<Vec<u8>>,
    max_len: usize,
) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
{
    while let Some(frame) = read_frame(&mut output, max_len).await? {
        let bytes = match frame {
            Frame::Line(line) if is_blank(&line) => continue,
            Frame::Line(line) => match lock(&firewall)?.on_server_message(&line) {
                ServerAction::Forward => line,
                ServerAction::Rewrite(msg) => serde_json::to_vec(&msg)?,
                ServerAction::Drop => continue,
            },
            Frame::TooLong => {
                lock(&firewall)?.on_oversized(Peer::Server);
                continue;
            }
        };
        if to_client.send(bytes).await.is_err() {
            break;
        }
    }
    Ok(())
}

async fn write_client<W>(mut queue: mpsc::Receiver<Vec<u8>>, mut out: W) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    while let Some(mut line) = queue.recv().await {
        line.push(b'\n');
        out.write_all(&line).await?;
        // Flush once the queue drains rather than after every line.
        if queue.is_empty() {
            out.flush().await?;
        }
    }
    out.flush().await
}

/// A panic while holding the lock leaves the firewall state unknown; stop
/// proxying rather than keep enforcing a possibly half-updated policy state.
fn lock(firewall: &Shared) -> io::Result<MutexGuard<'_, Firewall>> {
    firewall
        .lock()
        .map_err(|_| io::Error::other("firewall state poisoned by an earlier panic"))
}

fn is_blank(line: &[u8]) -> bool {
    line.iter().all(u8::is_ascii_whitespace)
}

fn log_task_end(side: &str, result: Result<io::Result<()>, tokio::task::JoinError>) {
    match result {
        Ok(Ok(())) => debug!("{side} stream closed"),
        Ok(Err(err)) => warn!("{side} stream failed: {err}"),
        Err(err) if err.is_cancelled() => {}
        Err(err) => warn!("{side} task failed: {err}"),
    }
}

/// The MCP stdio shutdown sequence, after the server's stdin has been closed:
/// wait, then SIGTERM, then wait again, then SIGKILL.
async fn shutdown(child: &mut Child) -> io::Result<ExitStatus> {
    if let Ok(status) = timeout(SHUTDOWN_GRACE, child.wait()).await {
        return status;
    }
    debug!("server ignored stdin close; sending SIGTERM");
    terminate(child);
    if let Ok(status) = timeout(SHUTDOWN_GRACE, child.wait()).await {
        return status;
    }
    warn!("server ignored SIGTERM; killing it");
    child.kill().await?;
    child.wait().await
}

#[cfg(unix)]
fn terminate(child: &mut Child) {
    if let Some(pid) = child.id().and_then(|pid| libc::pid_t::try_from(pid).ok()) {
        // SAFETY: kill(2) has no memory-safety preconditions. `id()` is only
        // Some while the child has not been reaped, so the pid cannot have
        // been recycled for another process.
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
}

#[cfg(not(unix))]
fn terminate(child: &mut Child) {
    let _ = child.start_kill();
}

/// Registers signal handlers up front, so a registration failure is a
/// startup error instead of an immediate "signal received".
#[cfg(unix)]
fn termination_signal() -> io::Result<impl Future<Output = ()>> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    let mut hup = signal(SignalKind::hangup())?;
    Ok(async move {
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
            _ = hup.recv() => {}
        }
    })
}

#[cfg(not(unix))]
fn termination_signal() -> io::Result<impl Future<Output = ()>> {
    Ok(async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    })
}

/// Mirrors the server's exit status, using the shell convention 128 + N for
/// death by signal N.
fn exit_code(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    1
}
