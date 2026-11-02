use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::os::unix::process::CommandExt;
use std::process::Command;

use anyhow::{bail, Result};
use futures::stream::{self, StreamExt};
use tokio::sync::watch;

use crate::client::{Client, Lookup};

const MAX_CONCURRENT_READS: usize = 8;

/// Returns unique op:// references found in env var values.
pub fn collect_op_refs(env: &[(String, String)]) -> Vec<&str> {
    let mut seen = HashSet::new();
    env.iter()
        .filter(|(_, v)| v.starts_with("op://"))
        .filter_map(|(_, v)| {
            if seen.insert(v.as_str()) {
                Some(v.as_str())
            } else {
                None
            }
        })
        .collect()
}

/// Groups references by the account they will be read from, keeping the order
/// each account was first seen in.
pub fn group_by_account<'a, F>(
    refs: &[&'a str],
    account_of: F,
) -> Vec<(Option<String>, Vec<&'a str>)>
where
    F: Fn(&str) -> Option<String>,
{
    let mut groups: Vec<(Option<String>, Vec<&'a str>)> = Vec::new();

    for reference in refs {
        let account = account_of(reference);
        match groups.iter_mut().find(|(a, _)| *a == account) {
            Some((_, group)) => group.push(reference),
            None => groups.push((account, vec![reference])),
        }
    }

    groups
}

/// Resolves all op:// references through the cache.
/// Returns a map from reference string to resolved value.
///
/// `account` is an explicit override applied to every reference. Left as `None`,
/// each reference gets the account its vault is configured for, which is what
/// lets one command mix secrets from several 1Password accounts.
///
/// Every `op read` is a separate process asking 1Password to authorize it, and
/// parallel reads with no session yet raise one biometric prompt each. So in
/// each account, the first reference that misses the cache is read on its own,
/// and the other misses wait for it and then reuse the session it established:
/// one prompt per account. A cached reference never counts as that first read,
/// because it starts no `op` process and so establishes no session.
///
/// Each miss is read as soon as the daemon claims it for us, and the only wait
/// before that is for the account's first read. A claim makes other clients
/// wait for this one, so collecting every claim before reading any could
/// deadlock two commands that each hold a secret the other is waiting for.
pub async fn resolve_refs(
    client: &Client,
    refs: &[&str],
    account: Option<&str>,
) -> Result<HashMap<String, String>> {
    let mut resolved = HashMap::new();
    let mut errors = Vec::new();

    for (_, group) in group_by_account(refs, |reference| client.account_for(reference, account)) {
        let first_read_taken = Cell::new(false);
        let (first_read_done, first_read_done_rx) = watch::channel(false);
        let (first_read_taken, first_read_done) = (&first_read_taken, &first_read_done);

        let results: Vec<_> = stream::iter(group)
            .map(|reference| {
                let mut first_read_done_rx = first_read_done_rx.clone();
                async move {
                    let result = match client.lookup(reference, account).await {
                        Err(e) => Err(e),
                        Ok(Lookup::Hit(value)) => Ok(value),
                        Ok(Lookup::Claimed(claim)) if !first_read_taken.replace(true) => {
                            let result = claim.read().await;
                            first_read_done.send_replace(true);
                            result
                        }
                        Ok(Lookup::Claimed(claim)) => {
                            let _ = first_read_done_rx.wait_for(|done| *done).await;
                            claim.read().await
                        }
                    };
                    (reference, result)
                }
            })
            .buffer_unordered(MAX_CONCURRENT_READS)
            .collect()
            .await;

        for (reference, result) in results {
            match result {
                Ok(value) => {
                    resolved.insert(reference.to_string(), value);
                }
                Err(e) => errors.push(format!("{}: {}", reference, e)),
            }
        }
    }

    if !errors.is_empty() {
        bail!(
            "failed to resolve {} secret(s):\n  {}",
            errors.len(),
            errors.join("\n  ")
        );
    }

    Ok(resolved)
}

/// Build the final environment with resolved values substituted in.
pub fn build_env(
    env: &[(String, String)],
    resolved: &HashMap<String, String>,
) -> Vec<(String, String)> {
    env.iter()
        .map(|(k, v)| {
            if let Some(secret) = resolved.get(v.as_str()) {
                (k.clone(), secret.clone())
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect()
}

/// Replace the current process with the given command and environment.
/// This function does not return on success.
pub fn exec_command(program: &str, args: &[String], env: &[(String, String)]) -> Result<()> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.env_clear();
    for (k, v) in env {
        cmd.env(k, v);
    }
    // exec replaces the process; if it returns, something went wrong
    let err = cmd.exec();
    bail!("exec failed: {}", err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::daemon::server::Server;

    /// A client of a real daemon, run in this process on a private socket,
    /// whose `op` logs when each read starts and ends.
    async fn client_with_daemon(test: &str) -> (Client, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let dir =
            std::env::temp_dir().join(format!("op-cache-run-{}-{}", test, std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let op = dir.join("op");
        std::fs::write(
            &op,
            "#!/bin/sh\n\
             log=\"$(dirname \"$0\")/log\"\n\
             echo \"start $2\" >> \"$log\"\n\
             sleep 0.3\n\
             echo \"end $2\" >> \"$log\"\n\
             echo \"value of $2\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();

        let config = Config {
            socket_path: dir.join("sock"),
            op_path: op.to_string_lossy().into_owned(),
            op_timeout_seconds: 10,
            ..Config::default()
        };
        // `ensure_daemon_running` trusts a pid file naming a live process.
        std::fs::write(config.pid_path(), std::process::id().to_string()).unwrap();

        let server = Server::new(config.clone());
        tokio::spawn(async move { server.run().await });
        while std::os::unix::net::UnixStream::connect(&config.socket_path).is_err() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        (Client::new(config), dir)
    }

    #[tokio::test]
    async fn resolve_refs_reads_the_first_miss_alone_when_the_first_reference_is_cached() {
        let (client, dir) = client_with_daemon("first-miss").await;
        let account = Some("work");
        client.read("op://v/cached/f", account).await.unwrap();
        std::fs::remove_file(dir.join("log")).unwrap();

        let refs = ["op://v/cached/f", "op://v/a/f", "op://v/b/f", "op://v/c/f"];
        let resolved = resolve_refs(&client, &refs, account).await;
        let log = std::fs::read_to_string(dir.join("log")).unwrap_or_default();
        std::fs::remove_dir_all(&dir).ok();

        let resolved = resolved.unwrap();
        for reference in refs {
            assert_eq!(resolved[reference], format!("value of {}", reference));
        }

        let log: Vec<&str> = log.lines().collect();
        assert_eq!(
            log.len(),
            6,
            "one read per miss, none for the cached one: {:?}",
            log
        );
        let first = log[0]
            .strip_prefix("start ")
            .expect("log opens with a read");
        assert_eq!(
            log[1],
            format!("end {}", first),
            "the first miss finishes before another read starts: {:?}",
            log
        );
    }

    #[test]
    fn group_by_account_splits_by_account() {
        let refs = vec!["op://Private/a/f", "op://Backend/b/f", "op://Private/c/f"];
        let groups = group_by_account(&refs, |r| {
            if r.starts_with("op://Backend/") {
                Some("work".to_string())
            } else {
                Some("personal".to_string())
            }
        });

        assert_eq!(
            groups,
            vec![
                (
                    Some("personal".to_string()),
                    vec!["op://Private/a/f", "op://Private/c/f"]
                ),
                (Some("work".to_string()), vec!["op://Backend/b/f"]),
            ]
        );
    }

    #[test]
    fn group_by_account_keeps_one_group_when_account_is_uniform() {
        let refs = vec!["op://Private/a/f", "op://TDS/b/f"];
        let groups = group_by_account(&refs, |_| None);

        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].1, refs);
    }

    #[test]
    fn group_by_account_empty_input() {
        let refs: Vec<&str> = vec![];
        assert!(group_by_account(&refs, |_| None).is_empty());
    }

    #[test]
    fn collect_op_refs_finds_op_values() {
        let env = vec![
            ("SECRET".into(), "op://vault/item/field".into()),
            ("PLAIN".into(), "hello".into()),
            ("ANOTHER".into(), "op://vault/other/key".into()),
        ];
        let refs = collect_op_refs(&env);
        assert_eq!(refs, vec!["op://vault/item/field", "op://vault/other/key"]);
    }

    #[test]
    fn collect_op_refs_empty_env() {
        let env: Vec<(String, String)> = vec![];
        let refs = collect_op_refs(&env);
        assert!(refs.is_empty());
    }

    #[test]
    fn collect_op_refs_ignores_non_op() {
        let env = vec![
            ("URL".into(), "https://example.com".into()),
            ("PATH".into(), "/usr/bin".into()),
        ];
        let refs = collect_op_refs(&env);
        assert!(refs.is_empty());
    }

    #[test]
    fn collect_op_refs_skips_partial_match() {
        let env = vec![
            ("URL".into(), "https://example.com/op://fake".into()),
            ("REAL".into(), "op://vault/item/field".into()),
        ];
        let refs = collect_op_refs(&env);
        assert_eq!(refs, vec!["op://vault/item/field"]);
    }

    #[test]
    fn collect_op_refs_deduplicates() {
        let env = vec![
            ("SECRET_A".into(), "op://vault/item/field".into()),
            ("SECRET_B".into(), "op://vault/item/field".into()),
            ("OTHER".into(), "op://vault/other/key".into()),
        ];
        let refs = collect_op_refs(&env);
        assert_eq!(refs, vec!["op://vault/item/field", "op://vault/other/key"]);
    }

    #[test]
    fn build_env_substitutes_resolved_values() {
        let env = vec![
            ("SECRET".into(), "op://vault/item/field".into()),
            ("PLAIN".into(), "hello".into()),
            ("ANOTHER".into(), "op://vault/other/key".into()),
        ];
        let mut resolved = HashMap::new();
        resolved.insert("op://vault/item/field".into(), "s3cret".into());
        resolved.insert("op://vault/other/key".into(), "k3y".into());

        let result = build_env(&env, &resolved);
        assert_eq!(result[0], ("SECRET".into(), "s3cret".into()));
        assert_eq!(result[1], ("PLAIN".into(), "hello".into()));
        assert_eq!(result[2], ("ANOTHER".into(), "k3y".into()));
    }

    #[test]
    fn build_env_substitutes_duplicate_refs() {
        let env = vec![
            ("SECRET_A".into(), "op://vault/item/field".into()),
            ("SECRET_B".into(), "op://vault/item/field".into()),
        ];
        let mut resolved = HashMap::new();
        resolved.insert("op://vault/item/field".into(), "s3cret".into());

        let result = build_env(&env, &resolved);
        assert_eq!(result[0], ("SECRET_A".into(), "s3cret".into()));
        assert_eq!(result[1], ("SECRET_B".into(), "s3cret".into()));
    }

    #[test]
    fn build_env_preserves_order() {
        let env = vec![
            ("A".into(), "1".into()),
            ("B".into(), "op://vault/b".into()),
            ("C".into(), "3".into()),
        ];
        let mut resolved = HashMap::new();
        resolved.insert("op://vault/b".into(), "2".into());

        let result = build_env(&env, &resolved);
        let keys: Vec<&str> = result.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["A", "B", "C"]);
    }

    #[test]
    fn build_env_leaves_unresolved_unchanged() {
        let env = vec![("X".into(), "op://vault/x".into())];
        let resolved = HashMap::new();
        let result = build_env(&env, &resolved);
        assert_eq!(result[0], ("X".into(), "op://vault/x".into()));
    }
}
