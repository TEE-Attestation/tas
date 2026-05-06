# Thales CipherTrust Manager (CTM) Certificates

This directory holds the TLS certificates used by the Thales CTM plugin to authenticate to a CipherTrust Manager instance. All certificate files are excluded from version control via `.gitignore` and must be placed here manually before starting the service.

## Expected files

| File | Description |
|---|---|
| `ca_cert.pem` | CA certificate that signed the CTM server certificate (used to verify the server's TLS identity) |
| `client_cert.pem` | Client public certificate used for certificate-based login |
| `client_key.pem` | Client private key paired with `client_cert.pem` |

These paths are referenced in `config/thales_ctm/thales_ctm.yaml`:

```yaml
ca_certfile: "certs/thales_ctm/ca_cert.pem"
auth_certfile: "certs/thales_ctm/client_cert.pem"
auth_keyfile: "certs/thales_ctm/client_key.pem"
```

> **Note:** Certificate-based login is only active when `certificate_login: true` is set in `thales_ctm.yaml`. When it is `false`, `client_cert.pem` and `client_key.pem` are not used, but `ca_cert.pem` is still required unless `verify_ssl: false`.

---

## Obtaining the CA certificate (`ca_cert.pem`)

The CA certificate comes from your CTM instance's local CA.

1. Log in to Thales CTM with an Admin account.
2. In the left-hand navigation, go to **CA → Local**.
3. If no local CA exists, create one.
4. Download the existing CA using the **⋯** menu on the right-hand side next to the certificate entry.
5. Save the downloaded PEM file as `certs/thales_ctm/ca_cert.pem`.

Reference: <https://thalesdocs.com/ctp/cm/2.8/admin/cm_admin/certificate-based-auth/index.html>

---

## Obtaining the client certificate and key (`client_cert.pem` / `client_key.pem`)

Certificate-based authentication requires that the CTM user account has a Login Certificate configured.

### Step 1 — Generate a key pair and CSR

```bash
# Generate a 2048-bit RSA private key
openssl genrsa -out certs/thales_ctm/client_key.pem 2048

# Create a certificate signing request (CSR)
openssl req -new \
  -key certs/thales_ctm/client_key.pem \
  -out /tmp/client.csr \
  -subj "/CN=<your-ctm-username>"
```

### Step 2 — Sign the CSR with the CTM local CA

Submit `/tmp/client.csr` to your CTM instance to be signed by the local CA:

1. Log in to Thales CTM as an Admin.
2. Go to **CA → Local** and select your CA.
3. Choose **Issue Certificate** (or equivalent option).
4. Upload the CSR and download the signed certificate.
5. Save the signed certificate as `certs/thales_ctm/client_cert.pem`.

> Alternatively, your Thales CTM administrator can generate the key pair and certificate directly in CTM and export them for you.

### Step 3 — Attach the certificate to the CTM user account

1. In Thales CTM, navigate to **Access Management → Users**.
2. Select the user account that TAS will authenticate as.
3. Under **Login Certificates**, add the contents of `client_cert.pem`.

Reference: <https://thalesdocs.com/ctp/cm/2.8/admin/cm_admin/certificate-based-auth/index.html>

---

## Enabling certificate-based login

In `config/thales_ctm/thales_ctm.yaml`, set:

```yaml
certificate_login: true
verify_ssl: true
```

When `certificate_login` is `false`, the plugin uses username/password authentication (via `THALES_CTM_USERNAME` / `THALES_CTM_PASSWORD` environment variables) and the client cert/key files are ignored.

---

## File permissions

Restrict access to the private key to prevent unauthorised reads:

```bash
chmod 600 certs/thales_ctm/client_key.pem
```
