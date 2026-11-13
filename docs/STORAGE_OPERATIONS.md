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
  "policy_authorization": "none",
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
| `policy_authorization` | `"none"` / `"etcd"` | Value of `TAS_POLICY_AUTHORIZATION` |
| `redis_persistence_active` | `true`, `false`, or `"unknown"` | Whether AOF is on in Redis. This field reports on Redis only, not on PostgreSQL. |
| `config_rewrite_succeeded` | `true`, `false`, or `null` | `true`: Redis `CONFIG REWRITE` succeeded. `false`: a `CONFIG SET` or `CONFIG REWRITE` command failed. `null`: TAS skipped setup because the backend is PostgreSQL or `TAS_REDIS_PERSISTENCE=false`. |
| `policy_storage.backend` | `"redis"` / `"postgresql"` | Policy store selected by `TAS_POLICY_BACKEND` |
| `policy_storage.reachable` | `true` / `false` | Whether Redis responds to `PING`, or PostgreSQL responds to `SELECT 1` on a fresh connection. In `etcd` mode, `etcd` must also return the expected format marker, and the publication store must respond. |

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
| `tas-pub:<namespace>:<id>` | None | Policy publications in `etcd` mode with the Redis backend. TAS returns `503` for an approved policy whose publication is missing. Upload the policy again. |
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
PostgreSQL keeps JSON documents in `tas_policies.document` and, in `etcd`
mode, in `tas_policy_publications.document`.
Neither TAS backend encrypts the policy documents. Protect database files
and backups with access controls and storage encryption.

1. **File permissions**: restrict access to each database data directory and
   backup file.
2. **Signed policies**: set `TAS_ENFORCE_SIGNED_POLICIES=true` and configure
   `TAS_POLICY_TRUST`. During attestation, TAS checks the signatures.
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
   with version `1` and that it can query `tas_policies`. In `etcd` protection
   mode, it also checks `tas_policy_publications`. TAS does not start if the
   database is unreachable, these checks fail, or the schema is absent.

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
   In `etcd` mode, the existing approvals point to publications in the old
   store. Stop every TAS instance and clear `/tas/policy-auth/`.
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

---

## Optional policy rollback protection

`TAS_POLICY_AUTHORIZATION=etcd` enables rollback protection for policy
documents. Keep the default `none` setting to not to use it.

In protected mode, TAS keeps two kinds of data:

- `etcd` holds one approval record for each active policy, under the fixed
  prefix `/tas/policy-auth/`.
- The selected Redis or PostgreSQL backend holds the policy documents as
  immutable publications. `etcd` does not replace the selected backend.

TAS serves a policy only when its `etcd` approval matches the stored
document. If someone restores an old copy of the policy database, the
approvals in `etcd` still show which policies were deleted or replaced, so
TAS refuses the old documents.

### How policy publications work

A publication is one immutable, serialised version of a policy document.
Creating or replacing a policy stores the document under a new, random
publication ID; it does not overwrite an existing publication. The policy's
`etcd` approval records which publication ID is currently active, along with
a digest of its document. `etcd` stores no policy document.

The Redis publication store represents a policy's publications as fields in a
hash:

| Backend | Location | Contents |
|---|---|---|
| Redis | `tas-pub:<namespace>:<policy-id>` | One hash field per publication ID; each field contains the serialised document. |
| PostgreSQL | `tas_policy_publications` | One row per publication, keyed by namespace, policy ID and publication ID. The document is in the `document` column. |

When TAS reads a policy in protected mode, it first reads the active approval
from `etcd`, then fetches the exact publication it names from Redis or
PostgreSQL. TAS checks that the document matches the approval's digest and
policy ID before using it. Other publications for that policy are not served.
If the approved publication is missing or does not match, TAS fails closed
with a policy-integrity error.

The publication store's `insert` operation is an internal, write-once
operation, not the policy-management `create` operation. It returns `false`
without changing the stored document if that publication ID already exists.
The `etcd` approval decides whether a policy ID is new or active; the
publication store only stores and retrieves immutable versions.

When a policy is deleted, TAS removes its `etcd` approval before cleaning up
its publications. This means an old or leftover publication is not active and
cannot be served without a matching approval.

### Where to run `etcd`

The intended deployment  mod is to  run `etcd` inside the same CVM with a TAS server. 
The policy database can then live outside the CVM,
for example on an external server or untrusted disk. Anyone who can change
that database can delete rows or restore an old backup, but they cannot
change the approvals in `etcd`, so TAS refuses revoked or replaced
documents.

> [!WARNING]
> Someone can also roll back the `etcd` data itself. An adversary who
> controls the host, such as a  hypervisor operator, can stop the CVM, restore an
> older copy of its disk, and boot it again. That restores the old `etcd`
> data, so policies revoked after that copy was taken become valid again.

Take appropriate action to protect the `etcd` data against rollback. For
example, run `etcd` from a trusted source outside the TAS CVM, such as a
host or service under your control that the same adversary cannot roll
back. TAS connects to it over HTTPS with the same settings.

> [!WARNING]
> Whatever the location, do not back up and restore `etcd` together with the
> policy database. Restoring an `etcd` snapshot is not supported unless you can
> reapply every later revocation from a trusted source.

### Requirements for every deployment

These apply whether you run one TAS instance or several:

1. Run `etcd` with HTTPS and authentication, in one of the locations
   described in [Where to run `etcd`](#where-to-run-etcd).
2. Provision `/tas/control/policy-auth-format` with the exact value `1`, using
   an `etcd` administrative identity. TAS checks this marker at startup and
   refuses to start if it is missing or has another value. Leave the
   `/tas/policy-auth/` prefix empty.
3. Create an `etcd` identity for TAS with read access to the marker key and
   read and write access to the `/tas/policy-auth/` prefix. TAS needs no other
   `etcd` permissions.
4. Install the standard TAS dependencies with `pip install -r requirements.txt`.
5. Configure `TAS_ETCD_ENDPOINTS`, `TAS_ETCD_CA_FILE`, `TAS_ETCD_USERNAME`,
   and `TAS_ETCD_PASSWORD`. For mutual TLS, configure both
   `TAS_ETCD_CERT_FILE` and `TAS_ETCD_KEY_FILE`. As with other TAS settings,
   you can set these in the `TAS_CONFIG_FILE` file or as environment
   variables, and environment variables take precedence. See
   `config/tas_config.yaml` for an example.
6. If `TAS_POLICY_BACKEND=postgresql`, apply
   `db/postgresql/schema_v1.sql`. This v1 schema includes both policy tables.
   A prerelease v1 database initialised from an earlier draft can rerun the
   script to add the publication table. Existing policies remain unchanged.

A single `etcd` member works, but it is not highly available. While `etcd` is
unreachable, policy reads, creates, deletes, and secret releases fail closed.
Use a three-member `etcd` cluster if TAS must keep working when one member
is down, and list the reachable members in `TAS_ETCD_ENDPOINTS`.

### Start a new TAS deployment with protection

Use this procedure when the policy backend has no policies yet.

1. Meet the [requirements for every deployment](#requirements-for-every-deployment).
2. Set `TAS_POLICY_AUTHORIZATION=etcd` in the TAS configuration before the
   first start. With several instances, set it on every instance and follow
   the [rules for several TAS instances](#rules-for-several-tas-instances).
3. Start TAS. TAS refuses to start if it cannot reach `etcd` or the format
   marker is wrong.
4. Check [`GET /management/status`](#persistence-status): `policy_authorization`
   must be `"etcd"` and `policy_storage.reachable` must be `true`.
5. Create policies as usual with `tas-policy` or the management API. Each
   create stores a publication and its `etcd` approval.

### Convert an existing TAS deployment to protection

Use this procedure when TAS already runs with `TAS_POLICY_AUTHORIZATION=none`
and has policies. Protected mode does not approve existing (legacy) policies
automatically. Until you re-create a legacy policy, protected mode cannot see
it, and attestation that needs it fails.

1. Meet the [requirements for every deployment](#requirements-for-every-deployment).
2. While TAS still runs in mode `none`, run `tas-policy list` in each
   namespace and record the policy IDs.
3. Collect a trusted, signed file for each recorded policy. Do not use
   copies read back from the database, because the database is not trusted.
4. Stop every TAS instance. Do not run instances in mode `none` and mode
   `etcd` at the same time.
5. Set `TAS_POLICY_AUTHORIZATION=etcd` on every instance and start them.
   TAS reads this setting only at startup.
6. Check [`GET /management/status`](#persistence-status) on each instance,
   as in the new-deployment procedure.
7. For each recorded policy, run `tas-policy delete` and then
   `tas-policy create` with the trusted file, through any one instance. The
   delete removes the legacy document. The create stores an approved
   publication. Other instances see it at once, without a restart.
8. Run `tas-policy list` and confirm that it shows every recorded policy.

Do not use `tas-policy update` for step 7. It starts with a `get`, and
protected mode cannot see legacy policies. Plan a maintenance window: each
policy is unavailable between its delete and its create.

### Rules for several TAS instances

Several TAS instances can share one `etcd` deployment. TAS needs no leader,
lock service, or clock synchronization between instances: `etcd`
conditional transactions settle concurrent writes. If two instances create
the same policy at once, one succeeds and the other returns `409`. If a
delete overlaps a create, the delete wins and the late create is rejected.

All instances that share an `etcd` deployment must meet these rules:

| Requirement | Reason |
|---|---|
| Use the same policy backend: the same Redis server or the same PostgreSQL database. | An `etcd` approval points to a publication in that backend. An instance with a different backend cannot find the publication and returns `503` with reason `policy_integrity_error`. |
| Serve one shared set of policies. | The `/tas/policy-auth/` prefix is fixed. Separate TAS deployments with different policies need separate `etcd` deployments. |
| Run with `TAS_POLICY_AUTHORIZATION=etcd` on every instance. | An instance in mode `none` ignores `etcd`, reads policies stored without `etcd` approval, and can serve policies that protected instances have revoked. |
| Use the same `TAS_ETCD_ENDPOINTS` and CA file. | Every instance must read the same approvals. Each instance can use its own `etcd` identity, as long as it has the same permissions. |

The [timeout settings](#timeouts-and-monitoring) can differ between
instances, because each instance applies them locally. Instances
behind a load balancer must also share the Redis server that stores nonces,
because a client can get its nonce from one instance and send its request to
another. This is an existing TAS requirement and does not depend on `etcd`.

### Timeouts and monitoring

`TAS_POLICY_OPERATION_TIMEOUT_SECONDS` bounds protected creates and deletes
independently of the CLI's HTTP timeout. `TAS_ETCD_TIMEOUT_SECONDS` controls
each individual `etcd` request and must be no greater than the operation
deadline. Monitor `policy_authorization` and `policy_storage.reachable` in
[`GET /management/status`](#persistence-status) on each instance.

### Disable rollback protection

TAS reads `TAS_POLICY_AUTHORIZATION` only at startup. With several
instances, apply each step to every instance before the next step. Keep the
signed files and IDs of every active policy before starting:

1. Stop every TAS instance.
2. Remove all legacy policy documents from the configured backend using
   trusted backend administration: the Redis keys `policy:<id>`,
   `certify-policy:<id>`, and `domain-policy:<id>`, or the `tas_policies`
   rows. This prevents revoked legacy documents
   from becoming visible again in mode `none`.
3. Start every instance with `TAS_POLICY_AUTHORIZATION=none`.
4. Re-create each intended active policy from its trusted signed file,
   through any one instance.
5. Before enabling protection again, stop every TAS instance, clear
   `/tas/policy-auth/`, and verify that the prefix is empty. Publications
   that no approval references do not authorize policies. You can remove
   them separately.

See [CONFIG.md](CONFIG.md) for the full configuration reference.