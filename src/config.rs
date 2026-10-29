use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_socket_path")]
    pub socket_path: PathBuf,

    #[serde(default = "default_ttl_seconds")]
    pub ttl_seconds: u64,

    #[serde(default = "default_max_entries")]
    pub max_entries: u64,

    #[serde(default = "default_op_path")]
    pub op_path: String,

    #[serde(default = "default_op_timeout_seconds")]
    pub op_timeout_seconds: u64,

    /// How long a failed read is answered from memory instead of running `op`
    /// again. 0 retries every time.
    #[serde(default = "default_failure_ttl_seconds")]
    pub failure_ttl_seconds: u64,

    #[serde(default)]
    pub accounts: Accounts,
}

/// Which 1Password account a secret reference belongs to.
///
/// A vault lives in exactly one account, so the mapping is a property of the
/// machine rather than of each `op://` reference. That keeps references in the
/// standard form `op` itself accepts, so the same string still works with
/// `op read` and `op run`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Accounts {
    /// Account used for any vault without an explicit mapping.
    #[serde(default)]
    pub default: Option<String>,

    /// Vault name to account, e.g. `Backend: tripledotstudios.1password.eu`.
    #[serde(default)]
    pub vaults: HashMap<String, String>,
}

/// The vault segment of `op://<vault>/<item>/<field>`.
pub fn vault_of(reference: &str) -> Option<&str> {
    let rest = reference.strip_prefix("op://")?;
    let vault = rest.split('/').next()?;
    if vault.is_empty() {
        None
    } else {
        Some(vault)
    }
}

impl Accounts {
    /// The account configured for a reference's vault, if any.
    pub fn for_reference(&self, reference: &str) -> Option<&str> {
        vault_of(reference)
            .and_then(|vault| self.vaults.get(vault))
            .map(String::as_str)
    }
}

fn default_socket_path() -> PathBuf {
    PathBuf::from("/tmp/op-cache.sock")
}

fn default_ttl_seconds() -> u64 {
    86400 // 24 hours
}

fn default_max_entries() -> u64 {
    1000
}

fn default_op_path() -> String {
    "op".to_string()
}

/// Long enough to answer a biometric prompt. A read blocks the shell that
/// started it, and `op` waiting on a locked 1Password never gives up by itself.
fn default_op_timeout_seconds() -> u64 {
    5
}

fn default_failure_ttl_seconds() -> u64 {
    60
}

impl Default for Config {
    fn default() -> Self {
        Self {
            socket_path: default_socket_path(),
            ttl_seconds: default_ttl_seconds(),
            max_entries: default_max_entries(),
            op_path: default_op_path(),
            op_timeout_seconds: default_op_timeout_seconds(),
            failure_ttl_seconds: default_failure_ttl_seconds(),
            accounts: Accounts::default(),
        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let config_path = Self::config_path()?;

        if config_path.exists() {
            let contents = std::fs::read_to_string(&config_path)?;
            let config: Config = serde_yaml::from_str(&contents)?;
            Ok(config)
        } else {
            Ok(Config::default())
        }
    }

    pub fn config_path() -> Result<PathBuf> {
        if let Some(proj_dirs) = directories::ProjectDirs::from("", "", "op-cache") {
            Ok(proj_dirs.config_dir().join("config.yaml"))
        } else {
            Ok(PathBuf::from("~/.config/op-cache/config.yaml"))
        }
    }

    pub fn pid_path(&self) -> PathBuf {
        self.socket_path.with_extension("pid")
    }

    pub fn log_path(&self) -> PathBuf {
        self.socket_path.with_extension("log")
    }
}
