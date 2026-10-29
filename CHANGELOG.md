# Changelog

## Unreleased

### Added
- `run` conceals resolved secrets in the command's output, replacing each with `<concealed by op-cache>`. This costs the `exec`: op-cache now supervises the command so it owns the stream being written to, giving it a pty when output is a terminal and pipes when it is not, and passing the command's exit code — or `128 + signal` — back to the shell. `--no-masking` restores the previous `exec` behaviour for commands that are meant to print a secret.
- `accounts` config section mapping vault names to 1Password accounts, so a reference resolves against the account that owns its vault. `op-cache run` can now resolve secrets from several accounts in one invocation, which previously failed because a single `--account`/`OP_ACCOUNT` was applied to every reference.
- `accounts.default` for the account used by vaults with no explicit mapping.
- `failure_ttl_seconds` (default 60): a failed read is answered from memory for this long instead of running `op` again, so shells started while 1Password is locked fail at once rather than each waiting out a timeout. `op-cache clear` forgets failures too.

### Changed
- `op_timeout_seconds` defaults to 5 instead of 30. A read blocks the shell that started it, and 5 seconds is enough to answer a biometric prompt.
- The daemon protocol gains `Lookup` and `Fail`. Stop a daemon left running by an earlier version (`op-cache stop`); it does not understand them.

### Fixed
- `op read` processes no longer pile up while 1Password is locked or a macOS permission prompt is unanswered. A timed-out read used to be abandoned, not killed, and stayed behind with the `op daemon` it had started: two processes per secret for every shell started meanwhile, until the user's process limit was reached. Timed-out reads are now killed with their `op daemon`.
- Concurrent reads of the same cold secret run `op read` once. The daemon lets the first client read it and holds the rest until the result is in; if that client goes away without reporting, the next one reads instead.
- `run` no longer raises a biometric prompt per reference on a cold cache. Reads are grouped by account and the first of each group is read on its own, so the rest reuse the session it establishes instead of each asking 1Password to authorize a process of its own.

## 0.2.0

### Added
- `--account` flag on `read` and `run` subcommands to target a specific 1Password account.
- Ambient `OP_ACCOUNT` environment variable is now included in cache key computation, preventing cross-account cache collisions.

### Fixed
- Cache entries are now partitioned by effective account (explicit `--account` or `OP_ACCOUNT` env var), fixing a bug where the same reference on different accounts could return a stale secret from the wrong account.

## 0.1.0

- Initial release: daemon-based caching proxy for `op read`, with `read`, `run`, `status`, `stats`, `clear`, and `stop` subcommands.
