# Redis Persistence

TAS stores security policies in Redis. By default, TAS automatically configures
Redis persistence at startup so policies survive Redis and host restarts. This
is done via Redis `CONFIG SET` commands — no manual Redis configuration is needed.

## What TAS configures by default

When `TAS_REDIS_PERSISTENCE=true` (the default), TAS issues these commands at
startup:

| Command | Effect |
|---------|--------|
| `CONFIG SET appendonly yes` | Enable AOF (Append-Only File). Every write is logged to an on-disk journal. |
| `CONFIG SET appendfsync everysec` | Fsync the AOF once per second. At most 1 second of data loss on crash. |
| `CONFIG SET save "3600 1 300 100 60 10000"` | Enable RDB snapshots as a backup safety net (every 60 s if ≥10 000 keys changed, every 300 s if ≥100, every 3600 s if ≥1). |

After CONFIG SET, TAS calls `CONFIG REWRITE` to write the settings into
Redis's own config file so they survive independent Redis restarts.

**If CONFIG REWRITE fails** (e.g. Redis has no config file, or ACLs block
the command), TAS logs a warning and continues. Persistence is active for
the current Redis session, but if Redis restarts independently the settings
revert to defaults and **policies will be lost**. Check the
`GET /management/status` endpoint — a `"config_rewrite_succeeded": false` response
means you must either grant CONFIG REWRITE permission or configure
persistence in your `redis.conf` manually.

## Monitoring persistence status

The `GET /management/status` endpoint (requires management API key) returns:

```json
{
  "redis_persistence_active": true,
  "config_rewrite_succeeded": true
}
```

| Field | Values | Meaning |
|-------|--------|---------|
| `redis_persistence_active` | `true` / `false` / `"unknown"` | Whether AOF is currently enabled in Redis |
| `config_rewrite_succeeded` | `true` / `false` / `null` | Whether CONFIG REWRITE succeeded at startup. `null` means persistence was not attempted (`TAS_REDIS_PERSISTENCE=false`). |

**Action required when `config_rewrite_succeeded` is `false`:**
- Grant the Redis user `CONFIG REWRITE` permission, or
- Add `appendonly yes` and `appendfsync everysec` to your `redis.conf` manually

## What data is protected

| Key pattern | TTL | Risk without persistence |
|-------------|-----|--------------------------|
| `policy:<type>:<id>` | None | **Lost forever** — must be re-uploaded manually |
| `certs:*`, `crl:*`, `tdx_collateral:*` | 48 h | Re-fetched automatically on cache miss |
| Nonces | 120 s | Ephemeral by design — no persistence needed |

Policies are the critical data. Without persistence, a Redis restart silently
destroys all stored attestation policies.

## How to disable

Set `TAS_REDIS_PERSISTENCE=false` in your environment or config file. TAS will
not issue any `CONFIG SET` commands.

You are then responsible for configuring Redis persistence yourself:

- **Bare-metal**: edit `/etc/redis/redis.conf`, set `appendonly yes` and your
  preferred `appendfsync` / `save` directives, then restart Redis.
- **Docker**: mount a custom `redis.conf` into the container.
- **Cloud-managed** (ElastiCache, Azure Cache, Memorystore): enable persistence
  via the provider's dashboard. `CONFIG SET` is typically blocked on managed
  services, so `TAS_REDIS_PERSISTENCE=false` is required. If TAS's CONFIG SET
  is rejected, it logs a warning and continues — you must ensure persistence is
  configured externally.

## Alternative strategies

### In-memory only (no persistence)

Set `TAS_REDIS_PERSISTENCE=false` and do **not** configure Redis persistence.
Policies are lost on restart. Use this if you have an external policy reload
mechanism (CI/CD pipeline, management API script, or a policy-as-code workflow).

### RDB-only

Periodic full snapshots, larger data-loss window, simpler. In your `redis.conf`:

```
appendonly no
save 3600 1 300 100 60 10000
```

### AOF with `appendfsync always`

Maximum durability — fsync on every write, zero data loss. Slower throughput.
In your `redis.conf`:

```
appendonly yes
appendfsync always
save ""
```

## Security considerations

With persistence enabled, policies are written to disk as cleartext JSON in
AOF and RDB files. To protect them:

1. **File permissions**: `chmod 700 /var/lib/redis`, owned by the Redis user.
2. **Signed policies**: Set `TAS_ENFORCE_SIGNED_POLICIES=true`. TAS re-verifies
   policy signatures at attestation time, so tampered AOF/RDB data is rejected.
3. **Redis authentication**: Set `TAS_REDIS_PASSWORD` to require AUTH.
4. **Redis ACLs** (Redis 6+): Restrict the TAS user to only the commands it
   needs.

See [CONFIG.md](CONFIG.md) for the full configuration reference.
