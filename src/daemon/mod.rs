pub mod cache;
pub mod server;

use std::fs::File;

use fork::{daemon, Fork};
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::error::Error;

use self::server::Server;

/// Daemonize and run the server.
/// Uses traditional double-fork daemonization which is safe because
/// the daemon is just a cache server - it doesn't need D-Bus or any
/// session resources.
pub fn daemonize(config: Config) -> Result<(), Error> {
    match daemon(false, false) {
        Ok(Fork::Parent(_)) => {
            // Parent exits immediately
            Ok(())
        }
        Ok(Fork::Child) => {
            // Child continues as daemon
            run_daemon(config)
        }
        Err(e) => Err(Error::SpawnFailed(format!("fork failed: {}", e))),
    }
}

/// Run the daemon in the foreground (for testing/debugging)
pub fn run_foreground(config: Config) -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("op_cache=debug".parse().unwrap()),
        )
        .init();

    run_daemon_inner(config)
}

fn run_daemon(config: Config) -> Result<(), Error> {
    // Setup logging to file
    let log_path = config.log_path();
    let file = File::create(&log_path)
        .map_err(|e| Error::Internal(format!("failed to create log file: {}", e)))?;

    tracing_subscriber::fmt()
        .with_writer(std::sync::Mutex::new(file))
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("op_cache=info".parse().unwrap()),
        )
        .init();

    run_daemon_inner(config)
}

fn run_daemon_inner(config: Config) -> Result<(), Error> {
    info!("daemon starting with pid {}", std::process::id());

    // Create tokio runtime
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Internal(format!("failed to create runtime: {}", e)))?;

    // Run server
    rt.block_on(async {
        let server = Server::new(config);
        server.run().await
    })
}

/// The daemon is running when its socket takes a connection. The pid file does
/// not tell: macOS deletes files in /tmp left unchanged for 3 days, and a client
/// trusting it then started a second daemon, which took over the socket and
/// left the first one running, unreachable.
pub fn is_running(config: &Config) -> bool {
    std::os::unix::net::UnixStream::connect(&config.socket_path).is_ok()
}

/// Get the PID of the running daemon
pub fn get_pid(config: &Config) -> Option<i32> {
    let pid_path = config.pid_path();

    if let Ok(contents) = std::fs::read_to_string(&pid_path) {
        contents.trim().parse::<i32>().ok()
    } else {
        None
    }
}
