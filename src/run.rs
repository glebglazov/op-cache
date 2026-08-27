use std::collections::{HashMap, HashSet};
use std::os::unix::process::CommandExt;
use std::process::Command;

use anyhow::{bail, Result};
use futures::stream::{self, StreamExt};

use crate::client::Client;

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

/// Resolves all op:// references concurrently (bounded) through the cache.
/// Returns a map from reference string to resolved value.
///
/// `account` is an explicit override applied to every reference. Left as `None`,
/// each reference gets the account its vault is configured for, which is what
/// lets one command mix secrets from several 1Password accounts.
pub async fn resolve_refs(
    client: &Client,
    refs: &[&str],
    account: Option<&str>,
) -> Result<HashMap<String, String>> {
    let results: Vec<_> = stream::iter(refs.iter().copied())
        .map(|reference| async move {
            let result = client.read(reference, account).await;
            (reference, result)
        })
        .buffer_unordered(MAX_CONCURRENT_READS)
        .collect()
        .await;

    let mut resolved = HashMap::new();
    let mut errors = Vec::new();

    for (reference, result) in results {
        match result {
            Ok(value) => {
                resolved.insert(reference.to_string(), value);
            }
            Err(e) => {
                errors.push(format!("{}: {}", reference, e));
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
