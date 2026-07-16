# Experimental: Certificate Flow Requirements

Status: Experimental

This document describes the experimental TAS certificate flow. It is intentionally not linked from existing documentation indexes and may change without notice.

## Endpoint

POST /alphav1/certify

The endpoint issues a TAS-signed workload certificate after successful attestation. It can also renew an unexpired TAS certificate when `renew_cert` is provided.

## Availability

The certificate API is only available when `TAS_CERT_ENABLED` is enabled. If certificate support is disabled, the certificate routes are not registered and the certificate plugin is not initialised.

## Request Requirements

A request must be JSON and must include:

- `tee-type`: TEE type, such as `intel-tdx` or `amd-sev-snp`
- `nonce`: fresh nonce from GET /alphav1/nonce
- `tee-evidence`: base64-encoded TEE attestation evidence
- `csr`: base64-encoded certificate signing request
- `policy-domain`: requested policy domain

Optional fields:

- `gpu-evidence`: GPU evidence list. Each entry must include `type`, `evidence`, and non-negative `device-index`
- `renew_cert`: PEM-encoded current TAS certificate for renewal

All requests require API authentication.

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

TAS validates the request, checks the nonce, sanitises the CSR, verifies attestation evidence, records evidence digest metadata, builds TAS certificate extensions, and signs a new certificate through the active certificate plugin.

The issued certificate receives a new SPIFFE ID:

```text
spiffe://<TAS_CERT_TRUST_DOMAIN>/<policy-domain>/<uuid>
```

`TAS_CERT_TRUST_DOMAIN` is the configured TAS trust domain. `policy-domain` is the policy domain from the request and attestation verification. `uuid` is a new UUID v4 for standard issuance.

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

Renewal does not skip attestation. TAS still requires a fresh nonce, fresh attestation evidence, a valid CSR, and a matching `policy-domain`.

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
  "policy-domain": "staging",
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
- `TAS_CERT_ENABLED` — Main feature flag for certificate issuance (default: `false`). When `false`, the `/alphav1/certify` route is not registered and the certificate provider plugin is not initialized. Set to `true` to enable the feature once a cert provider is configured. This feature is disabled by default until it is production-ready.
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
- `TAS_OID_ROOT` — Custom X.509 extension OID arc (default: `1.3.6.1.4.1.65993`).

## Notes

- This flow is experimental and is not a stable compatibility guarantee.
- Certificate endpoints currently use the `/alphav1` prefix.
- Renewal is an identity continuity check only; it does not replace attestation.
