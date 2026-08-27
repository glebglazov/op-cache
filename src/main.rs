mod cli;
mod client;
mod config;
mod daemon;
mod error;
mod mask;
mod protocol;
mod run;
mod spawn;
mod supervise;

use std::sync::Arc;

use anyhow::Result;
use clap::Parser;

use cli::{Cli, Command};
use client::Client;
use config::Config;

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = Config::load()?;

    match cli.command {
        Command::Read { reference, account } => cmd_read(config, &reference, account.as_deref()),
        Command::Run {
            account,
            no_masking,
            command,
        } => cmd_run(config, command, account.as_deref(), !no_masking),
        Command::Status => cmd_status(&config),
        Command::Stats => cmd_stats(config),
        Command::Clear => cmd_clear(config),
        Command::Stop => cmd_stop(config),
        Command::Daemon => cmd_daemon(config),
        Command::DaemonForeground => cmd_daemon_foreground(config),
    }
}

fn cmd_read(config: Config, reference: &str, account: Option<&str>) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        let client = Client::new(config);
        let value = client.read(reference, account).await?;
        print!("{}", value);
        Ok(())
    })
}

fn cmd_run(
    config: Config,
    command: Vec<String>,
    account: Option<&str>,
    masking: bool,
) -> Result<()> {
    let mut env: Vec<(String, String)> = std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
        .collect();
    let refs = run::collect_op_refs(&env);

    if refs.is_empty() {
        // No op:// references — just exec directly
        return run::exec_command(&command[0], &command[1..], &env);
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let resolved = rt.block_on(async {
        let client = Client::new(config);
        run::resolve_refs(&client, &refs, account).await
    })?;

    env = run::build_env(&env, &resolved);

    if !masking {
        return run::exec_command(&command[0], &command[1..], &env);
    }

    let patterns = mask::patterns(resolved.values().map(String::as_str));
    if patterns.is_empty() {
        // Nothing here is worth concealing, so keep the cheaper process model.
        return run::exec_command(&command[0], &command[1..], &env);
    }

    let masker = Arc::new(mask::Masker::new(&patterns)?);
    let code = supervise::run(&command[0], &command[1..], &env, masker)?;
    std::process::exit(code)
}

fn cmd_status(config: &Config) -> Result<()> {
    if daemon::is_running(config) {
        if let Some(pid) = daemon::get_pid(config) {
            println!("daemon running (pid {})", pid);
        } else {
            println!("daemon running");
        }
    } else {
        println!("daemon not running");
    }
    Ok(())
}

fn cmd_stats(config: Config) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        let client = Client::new(config);
        let stats = client.stats().await?;

        println!("Cache Statistics:");
        println!("  Entries: {}", stats.entries);
        println!("  Hits:    {}", stats.hits);
        println!("  Misses:  {}", stats.misses);
        println!("  Hit Rate: {:.1}%", stats.hit_rate * 100.0);

        Ok(())
    })
}

fn cmd_clear(config: Config) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        let client = Client::new(config);
        client.clear().await?;
        println!("cache cleared");
        Ok(())
    })
}

fn cmd_stop(config: Config) -> Result<()> {
    if !daemon::is_running(&config) {
        println!("daemon not running");
        return Ok(());
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    rt.block_on(async {
        let client = Client::new(config);
        match client.stop().await {
            Ok(()) => println!("daemon stopped"),
            Err(e) => {
                if e.to_string().contains("Connection reset") {
                    println!("daemon stopped");
                } else {
                    return Err(e.into());
                }
            }
        }
        Ok(())
    })
}

fn cmd_daemon(config: Config) -> Result<()> {
    daemon::daemonize(config)?;
    Ok(())
}

fn cmd_daemon_foreground(config: Config) -> Result<()> {
    daemon::run_foreground(config)?;
    Ok(())
}
