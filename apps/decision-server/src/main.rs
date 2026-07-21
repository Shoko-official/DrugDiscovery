#![deny(unsafe_code)]

use std::{
    env,
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
};

use bioworld_decision_server::{DecisionServerConfig, DecisionServerRuntime};

const CONTROL_ENVIRONMENT: &str = "BIOWORLD_DECISION_SERVER_CONFIG";

#[tokio::main]
async fn main() -> ExitCode {
    if emit_stdout("decision_server starting").is_err() {
        let _ = emit_stderr("decision_server failed");
        return ExitCode::FAILURE;
    }

    match run().await {
        Ok(()) if emit_stdout("decision_server stopped").is_ok() => ExitCode::SUCCESS,
        Err(_) => {
            let _ = emit_stderr("decision_server failed");
            ExitCode::FAILURE
        }
        Ok(()) => {
            let _ = emit_stderr("decision_server failed");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), ProcessFailure> {
    let mut signals = ShutdownSignals::register().map_err(|_| ProcessFailure)?;
    let control_path = control_path().ok_or(ProcessFailure)?;
    let config = tokio::select! {
        biased;
        _ = signals.wait() => {
            emit_stdout("decision_server stopping").map_err(|_| ProcessFailure)?;
            return Ok(());
        }
        result = DecisionServerConfig::load(control_path) => {
            result.map_err(|_| ProcessFailure)?
        }
    };
    let runtime = tokio::select! {
        biased;
        _ = signals.wait() => {
            emit_stdout("decision_server stopping").map_err(|_| ProcessFailure)?;
            return Ok(());
        }
        result = DecisionServerRuntime::prepare(config) => {
            result.map_err(|_| ProcessFailure)?
        }
    };

    emit_stdout("decision_server ready").map_err(|_| ProcessFailure)?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let serving = runtime.serve(async move {
        let _ = shutdown_rx.await;
    });
    tokio::pin!(serving);

    tokio::select! {
        biased;
        _ = signals.wait() => {
            emit_stdout("decision_server stopping").map_err(|_| ProcessFailure)?;
            let _ = shutdown_tx.send(());
            serving.await.map_err(|_| ProcessFailure)
        }
        result = &mut serving => result.map_err(|_| ProcessFailure),
    }
}

fn control_path() -> Option<PathBuf> {
    let path = PathBuf::from(env::var_os(CONTROL_ENVIRONMENT)?);
    if path.is_absolute() { Some(path) } else { None }
}

#[derive(Clone, Copy, Debug)]
struct ProcessFailure;

fn emit_stdout(event: &str) -> io::Result<()> {
    let mut output = io::stdout().lock();
    writeln!(output, "{event}")?;
    output.flush()
}

fn emit_stderr(event: &str) -> io::Result<()> {
    let mut output = io::stderr().lock();
    writeln!(output, "{event}")?;
    output.flush()
}

#[cfg(unix)]
struct ShutdownSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl ShutdownSignals {
    fn register() -> std::io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};

        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
        })
    }

    async fn wait(&mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => {}
            _ = self.terminate.recv() => {}
        }
    }
}

#[cfg(windows)]
struct ShutdownSignals {
    control_c: tokio::signal::windows::CtrlC,
    control_break: tokio::signal::windows::CtrlBreak,
    control_close: tokio::signal::windows::CtrlClose,
    control_shutdown: tokio::signal::windows::CtrlShutdown,
}

#[cfg(windows)]
impl ShutdownSignals {
    fn register() -> std::io::Result<Self> {
        use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close, ctrl_shutdown};

        Ok(Self {
            control_c: ctrl_c()?,
            control_break: ctrl_break()?,
            control_close: ctrl_close()?,
            control_shutdown: ctrl_shutdown()?,
        })
    }

    async fn wait(&mut self) {
        tokio::select! {
            _ = self.control_c.recv() => {}
            _ = self.control_break.recv() => {}
            _ = self.control_close.recv() => {}
            _ = self.control_shutdown.recv() => {}
        }
    }
}

#[cfg(not(any(unix, windows)))]
struct ShutdownSignals;

#[cfg(not(any(unix, windows)))]
impl ShutdownSignals {
    fn register() -> std::io::Result<Self> {
        Ok(Self)
    }

    async fn wait(&mut self) {
        let _ = tokio::signal::ctrl_c().await;
    }
}
