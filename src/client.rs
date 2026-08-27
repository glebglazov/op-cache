use std::time::Duration;

use tokio::net::UnixStream;
use tokio::process::Command;

use crate::config::Config;
use crate::error::Error;
use crate::protocol::{read_message, write_message, CacheStats, Request, Response};
use crate::spawn::ensure_daemon_running;

pub struct Client {
    config: Config,
}

impl Client {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    async fn connect(&self) -> Result<UnixStream, Error> {
        UnixStream::connect(&self.config.socket_path)
            .await
            .map_err(Error::ConnectionFailed)
    }

    async fn send_request(&self, request: Request) -> Result<Response, Error> {
        let mut stream = self.connect().await?;
        write_message(&mut stream, &request).await?;
        let response: Response = read_message(&mut stream).await?;
        Ok(response)
    }

    /// Resolve the account to read a reference with.
    ///
    /// Most specific wins: an explicit `--account`, then the account configured
    /// for the reference's vault, then `OP_ACCOUNT`, then the configured
    /// default. The vault mapping outranks `OP_ACCOUNT` because a vault lives in
    /// exactly one account, so a per-invocation override that contradicts it can
    /// only ever fail.
    fn effective_account(&self, reference: &str, explicit: Option<&str>) -> Option<String> {
        if let Some(acct) = explicit {
            return Some(acct.to_string());
        }
        if let Some(acct) = self.config.accounts.for_reference(reference) {
            return Some(acct.to_string());
        }
        std::env::var("OP_ACCOUNT")
            .ok()
            .filter(|v| !v.is_empty())
            .or_else(|| self.config.accounts.default.clone())
    }

    /// Hash the reference (and optional account) for use as cache key
    fn cache_key(reference: &str, account: Option<&str>) -> String {
        let input = match account {
            Some(acct) => format!("{}\0{}", acct, reference),
            None => reference.to_string(),
        };
        let hash = blake3::hash(input.as_bytes());
        hash.to_hex().to_string()
    }

    /// Read a secret, using cache if available
    pub async fn read(&self, reference: &str, account: Option<&str>) -> Result<String, Error> {
        // Validate reference format
        if !reference.starts_with("op://") {
            return Err(Error::InvalidReference(format!(
                "reference must start with 'op://': {}",
                reference
            )));
        }

        // Ensure daemon is running
        ensure_daemon_running(&self.config)?;

        let effective = self.effective_account(reference, account);
        let key = Self::cache_key(reference, effective.as_deref());

        // Check cache first
        let response = self.send_request(Request::Get { key: key.clone() }).await?;

        match response {
            Response::Hit { value } => Ok(value),
            Response::Miss => {
                // Cache miss - execute op read ourselves
                let value = self
                    .execute_op_read(reference, effective.as_deref())
                    .await?;

                // Store in cache
                let _ = self
                    .send_request(Request::Set {
                        key,
                        value: value.clone(),
                    })
                    .await;

                Ok(value)
            }
            _ => Err(Error::Protocol("unexpected response".to_string())),
        }
    }

    /// Execute op read command
    async fn execute_op_read(
        &self,
        reference: &str,
        account: Option<&str>,
    ) -> Result<String, Error> {
        let timeout = Duration::from_secs(self.config.op_timeout_seconds);
        let mut cmd = Command::new(&self.config.op_path);
        cmd.arg("read").arg(reference);
        if let Some(acct) = account {
            cmd.arg("--account").arg(acct);
        }
        let output = tokio::time::timeout(timeout, cmd.output())
        .await
        .map_err(|_| {
            Error::OpFailed(format!(
                "op read timed out after {}s for {}",
                self.config.op_timeout_seconds, reference
            ))
        })?
        .map_err(|e| Error::OpFailed(format!("failed to execute op: {}", e)))?;

        if output.status.success() {
            let value = String::from_utf8_lossy(&output.stdout)
                .trim_end()
                .to_string();
            Ok(value)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(Error::OpFailed(stderr.trim().to_string()))
        }
    }

    /// Get cache statistics
    pub async fn stats(&self) -> Result<CacheStats, Error> {
        ensure_daemon_running(&self.config)?;

        let response = self.send_request(Request::GetStats).await?;
        match response {
            Response::Stats(stats) => Ok(stats),
            _ => Err(Error::Protocol("unexpected response".to_string())),
        }
    }

    /// Clear the cache
    pub async fn clear(&self) -> Result<(), Error> {
        ensure_daemon_running(&self.config)?;

        let response = self.send_request(Request::ClearCache).await?;
        match response {
            Response::CacheCleared => Ok(()),
            _ => Err(Error::Protocol("unexpected response".to_string())),
        }
    }

    /// Stop the daemon
    pub async fn stop(&self) -> Result<(), Error> {
        let response = self.send_request(Request::Shutdown).await?;
        match response {
            Response::ShuttingDown => Ok(()),
            _ => Err(Error::Protocol("unexpected response".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{vault_of, Accounts};
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[test]
    fn cache_key_without_account() {
        let key = Client::cache_key("op://vault/item/field", None);
        let expected = blake3::hash(b"op://vault/item/field").to_hex().to_string();
        assert_eq!(key, expected);
    }

    #[test]
    fn cache_key_with_account() {
        let key = Client::cache_key("op://vault/item/field", Some("my.1password.com"));
        let expected = blake3::hash(b"my.1password.com\0op://vault/item/field")
            .to_hex()
            .to_string();
        assert_eq!(key, expected);
    }

    #[test]
    fn cache_key_different_accounts_differ() {
        let key_a = Client::cache_key("op://vault/item/field", Some("a.1password.com"));
        let key_b = Client::cache_key("op://vault/item/field", Some("b.1password.com"));
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn cache_key_account_vs_none_differ() {
        let with = Client::cache_key("op://vault/item/field", Some("my.1password.com"));
        let without = Client::cache_key("op://vault/item/field", None);
        assert_ne!(with, without);
    }

    /// `effective_account` reads the process-wide OP_ACCOUNT, so these cases
    /// cannot run concurrently without clobbering each other.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn client_with(accounts: Accounts) -> Client {
        Client::new(Config {
            accounts,
            ..Config::default()
        })
    }

    fn mapping(vault: &str, account: &str) -> Accounts {
        Accounts {
            default: None,
            vaults: HashMap::from([(vault.to_string(), account.to_string())]),
        }
    }

    #[test]
    fn vault_of_extracts_vault() {
        assert_eq!(vault_of("op://Backend/item/field"), Some("Backend"));
        assert_eq!(vault_of("op://Private/item/field"), Some("Private"));
    }

    #[test]
    fn vault_of_handles_vaults_with_spaces() {
        assert_eq!(vault_of("op://My Vault/item/field"), Some("My Vault"));
    }

    #[test]
    fn vault_of_rejects_non_references() {
        assert_eq!(vault_of("not-a-reference"), None);
        assert_eq!(vault_of("op://"), None);
        assert_eq!(vault_of("op:///item/field"), None);
    }

    #[test]
    fn effective_account_explicit_wins() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("OP_ACCOUNT", "env.1password.com");
        let client = client_with(mapping("Backend", "mapped.1password.com"));
        let result =
            client.effective_account("op://Backend/item/field", Some("explicit.1password.com"));
        std::env::remove_var("OP_ACCOUNT");
        assert_eq!(result.as_deref(), Some("explicit.1password.com"));
    }

    #[test]
    fn effective_account_uses_vault_mapping() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("OP_ACCOUNT");
        let client = client_with(mapping("Backend", "work.1password.eu"));
        let result = client.effective_account("op://Backend/item/field", None);
        assert_eq!(result.as_deref(), Some("work.1password.eu"));
    }

    #[test]
    fn effective_account_vault_mapping_outranks_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("OP_ACCOUNT", "env.1password.com");
        let client = client_with(mapping("Backend", "work.1password.eu"));
        let result = client.effective_account("op://Backend/item/field", None);
        std::env::remove_var("OP_ACCOUNT");
        assert_eq!(result.as_deref(), Some("work.1password.eu"));
    }

    #[test]
    fn effective_account_ignores_mapping_for_other_vaults() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("OP_ACCOUNT");
        let client = client_with(mapping("Backend", "work.1password.eu"));
        let result = client.effective_account("op://Private/item/field", None);
        assert_eq!(result, None);
    }

    #[test]
    fn effective_account_falls_back_to_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("OP_ACCOUNT", "env.1password.com");
        let client = client_with(Accounts::default());
        let result = client.effective_account("op://Private/item/field", None);
        std::env::remove_var("OP_ACCOUNT");
        assert_eq!(result.as_deref(), Some("env.1password.com"));
    }

    #[test]
    fn effective_account_falls_back_to_configured_default() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("OP_ACCOUNT");
        let client = client_with(Accounts {
            default: Some("my.1password.com".to_string()),
            vaults: HashMap::new(),
        });
        let result = client.effective_account("op://Private/item/field", None);
        assert_eq!(result.as_deref(), Some("my.1password.com"));
    }

    #[test]
    fn effective_account_none_when_unset() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("OP_ACCOUNT");
        let client = client_with(Accounts::default());
        let result = client.effective_account("op://Private/item/field", None);
        assert_eq!(result, None);
    }

    #[test]
    fn effective_account_ignores_empty_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("OP_ACCOUNT", "");
        let client = client_with(Accounts::default());
        let result = client.effective_account("op://Private/item/field", None);
        std::env::remove_var("OP_ACCOUNT");
        assert_eq!(result, None);
    }
}
