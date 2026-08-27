# Changelog

## Unreleased

### Added
- `accounts` config section mapping vault names to 1Password accounts, so a reference resolves against the account that owns its vault. `op-cache run` can now resolve secrets from several accounts in one invocation, which previously failed because a single `--account`/`OP_ACCOUNT` was applied to every reference.
- `accounts.default` for the account used by vaults with no explicit mapping.

### Fixed
- `run` no longer raises a biometric prompt per reference on a cold cache. Reads are grouped by account and the first of each group is read on its own, so the rest reuse the session it establishes instead of each asking 1Password to authorize a process of its own.

## 0.2.0

### Added
- `--account` flag on `read` and `run` subcommands to target a specific 1Password account.
- Ambient `OP_ACCOUNT` environment variable is now included in cache key computation, preventing cross-account cache collisions.

### Fixed
- Cache entries are now partitioned by effective account (explicit `--account` or `OP_ACCOUNT` env var), fixing a bug where the same reference on different accounts could return a stale secret from the wrong account.

## 0.1.0

- Initial release: daemon-based caching proxy for `op read`, with `read`, `run`, `status`, `stats`, `clear`, and `stop` subcommands.
