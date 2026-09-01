# Experimental: Certificate Flow Requirements

Status: Experimental

This document describes the experimental TAS certificate flow. It is intentionally not linked from existing documentation indexes and may change without notice.

## Endpoint

POST /alphav1/certify

The endpoint issues a TAS-signed workload certificate after successful attestation. It can also renew an unexpired TAS certificate when `renew_cert` is provided.

## Availability

The certificate API is only available when `TAS_CERTIFY_ENABLED` is enabled. If certificate support is disabled, the certificate routes are not registered and the certificate plugin is not initialised.

## Request Requirements

A request must be JSON and must include:

- `tee-type`: TEE type, such as `intel-tdx` or `amd-sev-snp`
- `nonce`: fresh nonce from GET /alphav1/nonce
- `tee-evidence`: base64-encoded TEE attestation evidence
- `csr`: base64-encoded certificate signing request
- `domain-policy`: id of the domain-policy the workload is requesting a certificate for

Optional fields:

- `policy-id`: id of a specific certify-policy to evaluate against. When present, TAS evaluates the attestation only against this policy, which must be one of the certify-policies referenced by the requested domain-policy. When absent, TAS tries every referenced certify-policy until one passes.
- `gpu-evidence`: GPU evidence list. Each entry must include `type`, `evidence`, and non-negative `device-index`
- `renew_cert`: PEM-encoded current TAS certificate for renewal

All requests require API authentication.

## Domain Policies and Certify Policies

The certify flow evaluates attestation against a **domain-policy** rather than a single policy id. These objects live in the `domain-policy:{id}` and `certify-policy:{id}` Redis keyspaces, kept completely separate from the secret-release `policy:*` store.

- A **domain-policy** is an object, identified by a `policy_id`, that groups certify-policy ids by TEE type under `certify_policies`, e.g. `{"amd-sev-snp": ["sev-baseline"], "intel-tdx": ["tdx-baseline"]}`. Its `policy_id` is what the agent supplies as `domain-policy` and what appears in the issued SPIFFE ID. At verification only the ids listed for the request's `tee-type` are considered.
- A **certify-policy** is an attestation policy with the same structure as a secret-release policy (metadata, `validation_rules`, optional `components`), but used exclusively by the certify flow.

A request succeeds when the attestation satisfies **at least one** certify-policy listed for its `tee-type` (logical OR). Certify-policies registered under a mismatched TEE type — or whose declared `policy_type` does not match the evidence — are skipped rather than evaluated, which avoids needless retrievals and failures. Supplying the optional `policy-id` narrows evaluation to a single certify-policy, which must be listed for the request's `tee-type`.

Both object types honour `TAS_ENFORCE_SIGNED_POLICIES` and are verified against `TAS_TRUSTED_KEYS`, exactly like secret-release policies. They are managed through dedicated, management-authenticated endpoints that are registered only when `TAS_CERTIFY_ENABLED` is set:

- `POST   /management/domain-policy/v0/store`
- `GET    /management/domain-policy/v0/get/<name>`
- `GET    /management/domain-policy/v0/list`
- `DELETE /management/domain-policy/v0/delete/<name>`
- `POST   /management/certify-policy/v0/store`
- `GET    /management/certify-policy/v0/get/<id>`
- `GET    /management/certify-policy/v0/list`
- `DELETE /management/certify-policy/v0/delete/<id>`

## CSR Requirements

TAS accepts PEM or DER CSRs after base64 decoding. The CSR must:

- Have a valid CSR signature as proof of possession
- Use an allowed key type: RSA 3072 bits or larger, or EC P-256/P-384
- Fit within `TAS_CERT_MAX_CSR_BYTES`
- Contain at most one Common Name
- Use a DNS-safe Common Name when one is present

TAS ignores unsupported CSR subject fields. DNS SAN entries are kept only when they are DNS-safe.

## Standard Certification Flow

For a normal certificate request, omit `renew_cert`.

TAS validates the request, checks the nonce, sanitises the CSR, resolves the named domain-policy, and verifies the attestation evidence against its referenced certify-policies (stopping at the first that passes, or only the `policy-id` one when supplied). It then records evidence digest metadata, builds TAS certificate extensions, and signs a new certificate through the active certificate plugin.

The issued certificate receives a new SPIFFE ID:

```text
spiffe://<TAS_CERT_TRUST_DOMAIN>/<domain-policy>/<uuid>
```

`TAS_CERT_TRUST_DOMAIN` is the configured TAS trust domain. `domain-policy` is the policy domain from the request and attestation verification. `uuid` is a new UUID v4 for standard issuance.

## Certificate Contents

The issued certificate contains:

- Subject Common Name from the CSR, or a generated `tas.<random>` name when absent
- Subject public key from the CSR
- Issuer name, authority key identifier, and signature suite from the active certificate plugin
- Validity with `notBefore` set to current TAS time minus `TAS_CERT_CLOCK_SKEW_SECONDS`, and `notAfter` set to current TAS time plus `TAS_CERT_VALIDITY_SECONDS`
- Subject Key Identifier
- Authority Key Identifier
- Critical Basic Constraints with `CA:false`
- Critical Key Usage with `digitalSignature`
- Subject Alternative Name with one SPIFFE URI and optional DNS SANs from the CSR
- Extended Key Usage with `clientAuth` and `serverAuth`
- TAS custom extensions for policy domain, policy digest, verified platforms, attestation time, and evidence digests

## Renewal Flow

For renewal, include `renew_cert`.

Renewal does not skip attestation. TAS still requires a fresh nonce, fresh attestation evidence, a valid CSR, and a matching `domain-policy`.

If renewal validation succeeds, TAS reuses the SPIFFE ID from the current certificate and issues a new certificate.

## Renewal Validation Requirements

The `renew_cert` certificate must:

- Parse as PEM X.509
- Be a leaf certificate with `basicConstraints CA:false`
- Include exactly one URI SAN
- Contain a SPIFFE URI using the `spiffe` scheme
- Use the configured TAS trust domain
- Use the same policy domain as the request
- Contain a canonical UUID v4
- Be within its validity period, allowing configured clock skew
- Verify against the active certificate plugin CA
- Use the same public key as the request CSR

If any renewal check fails, TAS returns HTTP 400.

## Minimal Request Example

```json
{
  "tee-type": "intel-tdx",
  "nonce": "...",
  "tee-evidence": "...base64...",
  "csr": "...base64...",
  "domain-policy": "staging",
  "renew_cert": "-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----"
}
```

Omit `renew_cert` for standard issuance.

## Response

A successful response returns HTTP 200 and includes:

- `certificate`: PEM-encoded issued certificate
- `ca_chain`: ordered CA chain
- `ca_bundle`: concatenated CA bundle

Common failure responses:

- HTTP 400 for malformed JSON, CSR, evidence, GPU evidence, or renewal input
- HTTP 403 for invalid nonce or failed attestation
- HTTP 500 when signing fails

## Certificate Issuance Configurations (`TAS_CERT_*`)

TAS uses the following configuration for its Certificate Issuance feature:
- `TAS_CERTIFY_ENABLED` — Main feature flag for certificate issuance (default: `false`). When `false`, the `/alphav1/certify` route is not registered and the certificate provider plugin is not initialized. Set to `true` to enable the feature once a cert provider is configured. This feature is disabled by default until it is production-ready.
- `TAS_CERT_PLUGIN` — Module name for the certificate signing backend (default: `tas_cert_local`).
- `TAS_CERT_PLUGIN_PREFIX` — Plugin discovery prefix (default: `tas_cert`).
- `TAS_CERT_CONFIG_FILE` — Configuration file path for the active cert plugin.
  For `tas_cert_local`, this YAML file may define `root_key_file`,
  `root_cert_file`, `ca_key_file`, and `ca_cert_file` to persist the local
  root and intermediate CA across restarts or load an externally generated
  CA hierarchy. When all four files exist, TAS loads and validates them;
  when none exist, TAS generates and writes them; a partial set fails
  startup. Concurrent generation is guarded by an exclusive lock file
  (`.tas_cert_local.lock`) in the key directory. Loaded certificates must be
  currently valid CA certificates with `keyCertSign`/`cRLSign` KeyUsage, the
  intermediate must chain to the root, and near-expiry certificates log a
  warning.

  > **Warning:** These files include the CA private keys, which are written
  > **unencrypted** (PKCS#8, no passphrase) with `0600` permissions. Protect
  > them at rest: store them on an encrypted volume, restrict directory
  > ownership to the TAS service account, keep them out of version control and
  > backups that are not access-controlled, and prefer an HSM or KMS-backed CA
  > for production. The bundled `tas_cert_local` plugin is intended for
  > development and testing only.
- `TAS_CERT_VALIDITY_SECONDS` — Lifespan of issued certificates in seconds (default: 300).
- `TAS_CERT_CLOCK_SKEW_SECONDS` — Backdating offset to handle clock skew (default: 90).
- `TAS_CERT_TRUST_DOMAIN` — Trust domain used for the URI SAN (default: `example.org`).
- `TAS_CERT_MAX_CSR_BYTES` — Reject CSRs larger than this byte length (default: 10000).
- `TAS_CERT_ALLOWED_KEY_TYPES` — Allowed CSR public key algorithms (default: `["RSA", "EC"]`).
- `TAS_CERTIFY_MAX_POLICIES` — Maximum number of certify-policies a domain-policy may reference; bounds the OR-evaluation loop (default: `32`).
- `TAS_OID_ROOT` — Custom X.509 extension OID arc (default: `1.3.6.1.4.1.65993`).

## Notes

- This flow is experimental and is not a stable compatibility guarantee.
- Certificate endpoints currently use the `/alphav1` prefix.
- Renewal is an identity continuity check only; it does not replace attestation.
