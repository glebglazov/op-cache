# op-cache

A fast caching proxy for 1Password CLI `op read` commands.

## Why?

`op read` is slow (~200-500ms) because it needs to communicate with the 1Password desktop app. If you're reading the same secret multiple times (e.g., in scripts), this adds up.

`op-cache` maintains a local daemon that caches secrets in memory, reducing repeated reads to ~1-2ms.

## Installation

```bash
cargo install --path .
```

Or build manually:

```bash
cargo build --release
# Binary at target/release/op-cache
```

## Usage

```bash
# Read a secret (auto-starts daemon if needed)
op-cache read op://vault/item/field

# Check daemon status
op-cache status

# View cache statistics
op-cache stats

# Clear the cache
op-cache clear

# Stop the daemon
op-cache stop
```

### Running Commands with Secrets

`op-cache run` scans your environment for variables with `op://` values, resolves them all concurrently through the cache, then replaces the current process with your command (via `exec`). If any resolution fails, the command is aborted.

```bash
# Run a command with secrets in env vars
export DATABASE_URL="op://Private/DB/url"
export API_KEY="op://Private/API/token"
op-cache run -- ./my-app

# Works with any command
op-cache run -- env | grep SECRET
op-cache run -- docker compose up
```

### Example

```bash
$ op-cache read op://Private/API/token
sk-abc123...

$ op-cache stats
Cache Statistics:
  Entries: 1
  Hits:    0
  Misses:  1
  Hit Rate: 0.0%

$ op-cache read op://Private/API/token  # Cache hit - fast!
sk-abc123...

$ op-cache stats
Cache Statistics:
  Entries: 1
  Hits:    1
  Misses:  1
  Hit Rate: 50.0%
```

## How It Works

```
┌─────────────┐                      ┌─────────────┐
│  op-cache   │◄── Unix Socket ────►│   Daemon    │
│  (client)   │   /tmp/op-cache.sock │  (cache)    │
└──────┬──────┘                      └─────────────┘
       │
       │ cache miss
       ▼
┌─────────────┐
│   op read   │
└─────────────┘
```

1. Client checks daemon cache for the secret
2. On cache hit: return immediately (~1-2ms)
3. On cache miss: client runs `op read`, stores result in cache, returns value
4. Daemon is auto-started on first use

The client (not the daemon) executes `op read`. This ensures proper access to your desktop session and 1Password app integration.

## Configuration

Config file: `~/.config/op-cache/config.yaml`

```yaml
socket_path: /tmp/op-cache.sock
ttl_seconds: 86400      # Cache TTL (default: 24 hours)
max_entries: 1000       # Max cached secrets
op_path: op             # Path to op CLI
op_timeout_seconds: 30  # Timeout for op commands
```

All settings are optional - sensible defaults are used.

### Multiple Accounts

If you are signed in to more than one 1Password account, `op read` cannot resolve
a reference without being told which account owns it. Map each vault to its
account once, and every reference to that vault resolves correctly:

```yaml
accounts:
  default: my.1password.com          # used for unmapped vaults
  vaults:
    Backend: work.1password.eu
    Shared: work.1password.eu
```

This matters most for `op-cache run`, which resolves every `op://` variable in
one pass. With a vault map, a single command can mix secrets from several
accounts:

```bash
export CONFLUENCE_TOKEN="op://Backend/Confluence/password"   # work account
export AWS_ACCESS_KEY_ID="op://Private/AWS/access_key_id"    # personal account
op-cache run -- terraform apply
```

The account for a reference is chosen most-specific-first: an explicit
`--account` flag, then the vault mapping, then `OP_ACCOUNT`, then
`accounts.default`. The vault mapping outranks `OP_ACCOUNT` because a vault lives
in exactly one account, so an ambient override that disagrees with it can only
fail.

Because the account is part of the cache key, mapping a vault to a different
account does not return stale secrets from the old one.

## Performance

| Operation | Latency |
|-----------|---------|
| Cache hit | ~1-2ms |
| Cache miss | ~200-500ms (op read time) |
| Cold start | ~50ms (daemon spawn) |

## Security Notes

- Secrets are cached in memory only (never written to disk)
- Cache is per-user (Unix socket permissions)
- TTL ensures secrets expire (default 24 hours)
- `op-cache clear` immediately purges all cached secrets
- Daemon stops cleanly on `op-cache stop` or system shutdown

## License

MIT
