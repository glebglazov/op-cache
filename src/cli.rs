use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "op-cache")]
#[command(about = "A fast caching proxy for 1Password CLI op read commands")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Read a secret (cached)
    Read {
        /// Secret reference (e.g., op://vault/item/field)
        reference: String,

        /// 1Password account to use (e.g., my.1password.com).
        /// Defaults to the account configured for the reference's vault.
        #[arg(long)]
        account: Option<String>,
    },

    /// Check if the daemon is running
    Status,

    /// Show cache statistics
    Stats,

    /// Clear the cache
    Clear,

    /// Stop the daemon
    Stop,

    /// Run a command with op:// env vars resolved through the cache
    #[command(trailing_var_arg = true)]
    Run {
        /// 1Password account to use for every reference (e.g., my.1password.com).
        /// Defaults to the account configured for each reference's vault.
        #[arg(long)]
        account: Option<String>,

        /// Print the command's output as-is instead of concealing resolved
        /// secrets in it. Needed when a command is meant to print one.
        #[arg(long)]
        no_masking: bool,

        /// Command and arguments to execute
        #[arg(required = true, num_args = 1..)]
        command: Vec<String>,
    },

    /// Run the daemon in background
    #[command(hide = true)]
    Daemon,

    /// Run the daemon in foreground (for debugging)
    #[command(hide = true)]
    DaemonForeground,
}
