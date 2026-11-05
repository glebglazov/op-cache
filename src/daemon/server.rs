use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;
use tracing::{debug, error, info};

use crate::config::Config;
use crate::error::Error;
use crate::protocol::{read_message, write_message, Request, Response};

use super::cache::{Cache, Claim, Lookup};

pub struct Server {
    config: Config,
    cache: Arc<Cache>,
}

impl Server {
    pub fn new(config: Config) -> Self {
        let cache = Arc::new(Cache::new(
            config.max_entries,
            config.ttl_seconds,
            config.failure_ttl_seconds,
        ));

        Self { config, cache }
    }

    pub async fn run(&self) -> Result<(), Error> {
        let path = &self.config.socket_path;
        let listener = match bind(path) {
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                // Replacing the socket of a daemon still serving it would leave
                // that daemon running, unreachable, for good.
                if UnixStream::connect(path).await.is_ok() {
                    return Err(Error::Internal(format!(
                        "another daemon is already listening on {:?}",
                        path
                    )));
                }
                // ponytail: two daemons replacing the same stale socket at once
                // can still orphan one; a stale socket is only left by a crash.
                let _ = std::fs::remove_file(path);
                bind(path)
            }
            result => result,
        }
        .map_err(|e| Error::Internal(format!("failed to bind socket: {}", e)))?;

        // Verify permissions (belt and suspenders)
        if let Err(e) = std::fs::set_permissions(
            &self.config.socket_path,
            std::fs::Permissions::from_mode(0o600),
        ) {
            let _ = std::fs::remove_file(&self.config.socket_path);
            return Err(Error::Internal(format!("failed to set socket permissions: {}", e)));
        }

        // Written only once the socket is ours, so a daemon that finds another
        // one running leaves that one's pid file alone.
        std::fs::write(self.config.pid_path(), format!("{}\n", std::process::id()))
            .map_err(|e| Error::Internal(format!("failed to write pid file: {}", e)))?;

        info!("daemon listening on {:?}", self.config.socket_path);

        // Setup shutdown signal
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let shutdown_tx = Arc::new(shutdown_tx);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, _addr)) => {
                            let cache = Arc::clone(&self.cache);
                            let mut conn_shutdown_rx = shutdown_rx.clone();
                            let conn_shutdown_tx = Arc::clone(&shutdown_tx);

                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(
                                    stream,
                                    cache,
                                    &mut conn_shutdown_rx,
                                    conn_shutdown_tx,
                                ).await {
                                    debug!("connection error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("accept error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("shutdown signal received");
                        break;
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("ctrl-c received, shutting down");
                    let _ = shutdown_tx.send(true);
                    break;
                }
            }
        }

        // Cleanup socket
        let _ = std::fs::remove_file(&self.config.socket_path);
        let _ = std::fs::remove_file(self.config.pid_path());

        Ok(())
    }
}

/// Binds with a restrictive umask, so the socket is never reachable by others.
fn bind(path: &std::path::Path) -> std::io::Result<UnixListener> {
    // The umask is the process's: two binds overlapping would leave it at 0o177.
    static UMASK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = UMASK.lock().unwrap_or_else(|e| e.into_inner());
    let old_umask = unsafe { libc::umask(0o177) };
    let result = UnixListener::bind(path);
    unsafe { libc::umask(old_umask) };
    result
}

async fn handle_connection(
    mut stream: UnixStream,
    cache: Arc<Cache>,
    shutdown_rx: &mut watch::Receiver<bool>,
    shutdown_tx: Arc<watch::Sender<bool>>,
) -> Result<(), Error> {
    // Held while this client reads a key; dropped with the connection.
    let mut claim: Option<Claim> = None;

    loop {
        tokio::select! {
            result = read_message::<_, Request>(&mut stream) => {
                let request = match result {
                    Ok(req) => req,
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        return Ok(());
                    }
                    Err(e) => {
                        return Err(Error::Protocol(e.to_string()));
                    }
                };

                debug!("received request: {:?}", request);

                let response = handle_request(&request, &cache, &mut claim).await;
                let is_shutdown = matches!(request, Request::Shutdown);

                write_message(&mut stream, &response).await?;

                if is_shutdown {
                    info!("shutdown request received, signaling main loop");
                    let _ = shutdown_tx.send(true);
                    return Ok(());
                }
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    return Ok(());
                }
            }
        }
    }
}

async fn handle_request(request: &Request, cache: &Cache, claim: &mut Option<Claim>) -> Response {
    match request {
        Request::Get { key } => {
            if let Some(value) = cache.get(key).await {
                Response::Hit { value }
            } else {
                Response::Miss
            }
        }
        Request::Lookup { key } => match cache.lookup(key).await {
            Lookup::Hit(value) => Response::Hit { value },
            Lookup::Failed(error) => Response::Failed { error },
            Lookup::Claimed(claimed) => {
                *claim = Some(claimed);
                Response::Claimed
            }
        },
        Request::Set { key, value } => {
            cache.insert(key, value.clone()).await;
            release(claim, key);
            Response::Stored
        }
        Request::Fail { key, error } => {
            cache.insert_failure(key, error.clone()).await;
            release(claim, key);
            Response::Stored
        }
        Request::Ping => Response::Pong,
        Request::ClearCache => {
            cache.clear();
            Response::CacheCleared
        }
        Request::GetStats => Response::Stats(cache.stats()),
        Request::Shutdown => Response::ShuttingDown,
    }
}

/// Gives up the claim on `key` once its result is stored, which wakes the
/// clients waiting for it.
fn release(claim: &mut Option<Claim>, key: &str) {
    if claim.as_ref().is_some_and(|c| c.key() == key) {
        *claim = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    fn config(test: &str) -> Config {
        let dir =
            std::env::temp_dir().join(format!("op-cache-server-{}-{}", test, std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Not left to the umask: a daemon binding in another test sets it to 0o177.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _ = std::fs::remove_file(dir.join("sock"));
        let _ = std::fs::remove_file(dir.join("sock.pid"));
        Config {
            socket_path: dir.join("sock"),
            ..Config::default()
        }
    }

    async fn start(config: &Config) {
        let server = Server::new(config.clone());
        tokio::spawn(async move { server.run().await });
        while std::os::unix::net::UnixStream::connect(&config.socket_path).is_err() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn second_daemon_leaves_the_running_one_alone() {
        let config = config("second");
        start(&config).await;
        let socket = std::fs::metadata(&config.socket_path).unwrap().ino();

        let second = tokio::time::timeout(Duration::from_secs(2), Server::new(config.clone()).run())
            .await
            .expect("the second daemon took over the socket and kept running");

        assert!(second.is_err());
        assert_eq!(std::fs::metadata(&config.socket_path).unwrap().ino(), socket);
        let mut stream = UnixStream::connect(&config.socket_path).await.unwrap();
        write_message(&mut stream, &Request::Ping).await.unwrap();
        let response: Response = read_message(&mut stream).await.unwrap();
        assert!(matches!(response, Response::Pong));
    }

    /// macOS deletes files in /tmp left unchanged for 3 days, and reading one
    /// does not count as a change.
    #[tokio::test]
    async fn daemon_is_running_without_its_pid_file() {
        let config = config("nopid");
        start(&config).await;
        let _ = std::fs::remove_file(config.pid_path());

        assert!(crate::daemon::is_running(&config));
    }
}
