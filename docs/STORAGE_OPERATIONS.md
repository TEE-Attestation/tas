# Storage Operations

TAS stores policies in Redis by default, or in PostgreSQL when
`TAS_POLICY_BACKEND=postgresql`. This applies to all three policy namespaces
(`policy`, `certify-policy`, and `domain-policy`).

Both modes need **Redis 6.2 or later**. TAS uses Redis for nonces, rate
limits, collateral caches, and plugin locks. Redis provides the `GETDEL`
command for atomic nonce validation.

## Select the policy store

> [!IMPORTANT]
> TAS uses only one policy store at a time. A change to `TAS_POLICY_BACKEND`
> does not move your policies. After the change, TAS cannot see the policies
> in the previous store. Follow [Change the Backend](#4-change-the-backend)
> before you change this setting.

`TAS_POLICY_BACKEND` selects the policy store: `redis` (the default) or
`postgresql`. TAS reads and writes policies only in the selected store:

- TAS saves a new policy only in the selected store. TAS does not copy it to
  the other store.
- If the selected store is unavailable, policy requests fail with an error.
  TAS does not try the other store instead.

The management list endpoints read policies one at a time. Redis uses `SCAN`
and PostgreSQL uses a server-side cursor. Thus TAS never loads all policy
documents into memory at once. The response still contains the full list and
count. If the store fails partway through, the endpoint returns an error, not
a partial list.

## Redis persistence at startup

TAS configures persistence on the primary Redis instance only when both of
these settings apply:

- `TAS_POLICY_BACKEND=redis` (the default).
- `TAS_REDIS_PERSISTENCE=true` (the default).

At startup, TAS issues these commands:

| Command | Effect |
|---------|--------|
| `CONFIG SET appendonly yes` | Enable the append-only file (AOF) to record writes. |
| `CONFIG SET appendfsync everysec` | Flush the AOF to disk once per second. A crash can lose about one second of writes. |
| `CONFIG SET save "3600 1 300 100 60 10000"` | Save an RDB snapshot after 3600 seconds with 1 change, 300 seconds with 100 changes, or 60 seconds with 10000 changes. |

After CONFIG SET, TAS calls `CONFIG REWRITE` to write the settings into
Redis's own config file so they survive independent Redis restarts.

If `CONFIG REWRITE` fails, TAS logs a warning and continues. The successful
`CONFIG SET` commands still apply to the current Redis process. After a
restart, Redis uses its saved configuration, which can leave persistence off.
Policy loss depends on that configuration and the files on disk.

If a `CONFIG SET` command fails, TAS also logs a warning and continues.
Earlier commands can still have succeeded. Check the Redis settings before you
rely on persistence.

With `TAS_POLICY_BACKEND=postgresql`, TAS skips these commands regardless of
`TAS_REDIS_PERSISTENCE`. This does not turn off persistence that Redis already
has. TAS never configures persistence on the optional ephemeral Redis
instance (`TAS_EPHEMERAL_REDIS_URI`).

## Persistence status

The `GET /management/status` endpoint (requires management API key) returns:

```json
{
  "redis_persistence_active": true,
  "config_rewrite_succeeded": true,
  "policy_storage": {
    "backend": "redis",
    "reachable": true
  }
}
```

| Field | Values | Description |
|-------|--------|---------|
| `redis_persistence_active` | `true`, `false`, or `"unknown"` | Whether AOF is on in Redis. This field reports on Redis only, not on PostgreSQL. |
| `config_rewrite_succeeded` | `true`, `false`, or `null` | `true`: Redis `CONFIG REWRITE` succeeded. `false`: a `CONFIG SET` or `CONFIG REWRITE` command failed. `null`: TAS skipped setup because the backend is PostgreSQL or `TAS_REDIS_PERSISTENCE=false`. |
| `policy_storage.backend` | `"redis"` / `"postgresql"` | Policy store selected by `TAS_POLICY_BACKEND` |
| `policy_storage.reachable` | `true` / `false` | Whether Redis responds to `PING`, or PostgreSQL responds to `SELECT 1` on a fresh connection |

These checks do not prove that Redis can save writes or that PostgreSQL has
durable storage and the required write permissions. The Redis fields describe
the primary instance, not the optional ephemeral instance.
`redis_persistence_active` is `"unknown"` if TAS cannot read the Redis
`appendonly` configuration.

When `config_rewrite_succeeded` is `false`, inspect the startup log to
identify the failed command. Grant the required Redis permissions or
configure `appendonly`, `appendfsync`, and `save` in `redis.conf`.

## Data in Redis

| Key pattern | TTL | Effect of key loss |
|-------------|-----|--------------------|
| `policy:<id>`, `certify-policy:<id>`, `domain-policy:<id>` | None | Restore policies from a backup or upload them again. These keys apply only to the Redis policy backend. |
| `certs:*` | None | TAS fetches certificates again on a cache miss. |
| `crl:*`, `tdx_collateral:*` | 48 hours | TAS fetches collateral again on a cache miss. |
| `nonce:<64-hex>` | `TAS_NONCE_EXPIRATION_SECONDS` (default: 120 seconds) | Clients must ask for new nonces. |

Without Redis persistence, a Redis restart loses the policies in that
instance. It does not affect policies in PostgreSQL. Caches use the primary
Redis instance. Nonces and rate limits use the optional ephemeral instance
when you configure it, or the primary instance otherwise.

TAS stores nonces under the `nonce:` prefix (`nonce:<64 lowercase hex>`)
with `SET ... EX ... NX`. TAS accepts only 64 lowercase hexadecimal
characters after it removes one pair of JSON quotes for compatibility with
older agents. TAS consumes the nonce atomically with `GETDEL`. It does not
read legacy keys without the `nonce:` prefix.

## Skip automatic Redis setup

Set `TAS_REDIS_PERSISTENCE=false` in your environment or config file. TAS then
does not send the persistence commands above, and Redis keeps its current
settings.

This setting does not undo earlier changes. If TAS started before with the
default setting, `CONFIG REWRITE` saved `appendonly yes` in `redis.conf`, and
persistence stays on. To turn persistence off, change the Redis configuration
yourself. Redis also keeps its AOF and RDB files on disk until you delete them.

With the Redis policy backend, configure persistence outside TAS:

- **Bare-metal**: set `appendonly yes` and your preferred `appendfsync` and
  `save` directives in `/etc/redis/redis.conf`. Restart Redis.
- **Docker**: mount a custom `redis.conf` into the container.
- **Managed Redis**: check which persistence and backup options your service
  supports. Use `TAS_REDIS_PERSISTENCE=false` if the service blocks the
  configuration commands.

Some managed services offer no persistence. Plan policy recovery or use
PostgreSQL in that case.

## Redis persistence alternatives

These settings affect Redis only, not PostgreSQL.
Set `TAS_REDIS_PERSISTENCE=false` before you use them. Otherwise, TAS
overwrites them with its defaults at startup when Redis is the policy backend.

### In-memory only (no persistence)

Set `TAS_REDIS_PERSISTENCE=false`. To disable persistence in Redis itself,
set `appendonly no` and `save ""` in its configuration.
A restart then loses the policies in Redis. Use this mode only if you can
restore the policies through the management API.

### RDB-only

Periodic full snapshots, larger data-loss window, simpler. In your `redis.conf`:

```
appendonly no
save 3600 1 300 100 60 10000
```

### AOF with `appendfsync always`

Redis flushes the AOF to disk on every write. This reduces the crash-loss
window but can lower throughput. It does not protect against disk loss or
storage hardware that fails to honor flush requests. In your `redis.conf`:

```
appendonly yes
appendfsync always
save ""
```

## Security considerations

Redis writes JSON documents to AOF and RDB files when persistence is on.
PostgreSQL keeps JSON documents in the `tas_policies.document` column.
Neither TAS backend encrypts the policy documents. Protect database files
and backups with access controls and storage encryption.

1. **File permissions**: restrict access to each database data directory and
   backup file.
2. **Signed policies**: set `TAS_ENFORCE_SIGNED_POLICIES=true` and configure
   `TAS_TRUSTED_KEYS`. During attestation, TAS checks the signatures.
   Signatures do not replace database access controls or backups.
3. **Redis authentication**: set a password on Redis with `requirepass` or an
   ACL user. Set `TAS_REDIS_PASSWORD` to the same password.

   `TAS_REDIS_PASSWORD` is only the password that TAS sends to Redis. It does
   not set a password on Redis. If Redis has no password, any client that
   connects without a password gets access. If TAS then sends a password,
   Redis rejects it and TAS does not start.
4. **Database permissions**: restrict each database account to the commands
   and tables that TAS needs.

---

## PostgreSQL Policy Storage

This section applies when `TAS_POLICY_BACKEND=postgresql`. Read
[Select the policy store](#select-the-policy-store) first.

### 1. Local Deployment and Schema Setup

1. Create a PostgreSQL database. Apply the versioned schema file before you
   start TAS:

   ```bash
   psql "postgresql://tas@localhost:5432/tas" \
     -v ON_ERROR_STOP=1 \
     -f db/postgresql/schema_v1.sql
   ```

2. Configure TAS to use PostgreSQL:

   ```bash
   export TAS_POLICY_BACKEND="postgresql"
   export TAS_POSTGRES_DSN="postgresql://tas@localhost:5432/tas"
   export TAS_POSTGRES_CONNECT_TIMEOUT_SECONDS=5
   export TAS_POSTGRES_STATEMENT_TIMEOUT_SECONDS=5
   ```

   At startup, TAS checks that `tas_schema_version` contains exactly one row
   with version `1` and that it can query `tas_policies`. TAS does not start
   if the database is unreachable, these checks fail, or the schema is absent.

   TAS uses `TAS_POSTGRES_CONNECT_TIMEOUT_SECONDS` when opening a connection
   unless the DSN explicitly sets `connect_timeout`. Policy statements use
   `TAS_POSTGRES_STATEMENT_TIMEOUT_SECONDS` unless the DSN `options` explicitly
   sets `statement_timeout`, for example:
   `options='-c statement_timeout=10s'`. In either case, the DSN setting
   takes precedence over the TAS setting. Both TAS timeout settings are in
   seconds and must be positive integers.

### 2. PostgreSQL Durability Settings

Make sure that your PostgreSQL instance uses durable storage settings in
`postgresql.conf` and stores its data directory (`PGDATA`) on persistent
storage:

```ini
fsync = on
synchronous_commit = on
full_page_writes = on
```

A standalone PostgreSQL instance does not protect against permanent
host or disk loss without regular backups or replication.

### 3. Backup and Restore

Back up the policy database with `pg_dump`:

```bash
pg_dump "$TAS_POSTGRES_DSN" --format=plain --file=tas_policies_backup.sql
```

Restore into an empty database with `psql`. Do not apply `schema_v1.sql`
first, because the dump already contains the schema:

```bash
psql "$TAS_POSTGRES_DSN" -v ON_ERROR_STOP=1 -f tas_policies_backup.sql
```

### 4. Change the Backend

A change to `TAS_POLICY_BACKEND` does not copy policies between stores.
The management API also uses only the selected store. To change the backend:

1. Pause policy changes and attestation traffic.
2. Export the required policy documents through the current management API.
   Include all three namespaces that your deployment uses.
3. Prepare the new store. For PostgreSQL, apply the schema as described above.
4. Set `TAS_POLICY_BACKEND` and the connection settings for the new store.
5. Restart all TAS workers with the new configuration. Keep client traffic
   paused.
6. Upload the policy documents through the management API. Keep the original
   signatures and policy IDs.
7. Check the policy contents in each namespace and test attestation.
8. Resume traffic and policy changes.

Keep the previous store and configuration until you check the new
deployment. A rollback must account for any policy changes in the new store;
TAS does not copy those changes back.

See [CONFIG.md](CONFIG.md) for the full configuration reference.
