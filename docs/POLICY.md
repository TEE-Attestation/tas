# TAS Policy Management Guide

This guide explains how to create, sign, and register security policies in the TEE Attestation Service (TAS).

## Table of Contents

- [Overview](#overview)
- [Policy Structure](#policy-structure)
- [Signing Policies](#signing-policies)
- [Registering Policies](#registering-policies)
- [Validation Rule Types](#validation-rule-types)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Overview

TAS policies define the security requirements that TEE attestation evidence must meet. Policies consist of:

- **Metadata**: Descriptive information about the policy
- **Validation Rules**: Specific attestation requirements (measurements, versions, etc.)
- **Digital Signature**: Optional but recommended for integrity verification

Policies are stored in Redis and referenced during attestation validation to determine if TEE evidence meets the required security standards.

## Policy Structure

### Example Policy Format

```json
{
  "metadata": {
    "name": "SEV Example Policy",
    "version": "1.0",
    "description": "Policy description",
    "created_date": "2024-09-09",
    "last_updated": "2024-09-09"
  },
  "validation_rules": {
    "measurement": {
      "exact_match": "a1b2c3d4e5f6789..."
    },
    "vmpl": {
      "exact_match": 0
    },
    "policy": {
      "migrate_ma_allowed": false,
      "debug_allowed": false,
      "smt_allowed": true
    },
    "platform_info": {
      "ecc_enabled": {
        "boolean": true
      },
      "tsme_enabled": {
        "boolean": true
      },
      "alias_check_complete": {
        "boolean": true
      },
      "smt_enabled": {
        "boolean": true
      }
    },
  },
  "signature": {
    "algorithm": "SHA384",
    "padding": "PSS",
    "value": "base64-encoded-signature"
  }
}
```

### Required Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `policy.metadata` | object | Yes | Policy metadata |
| `policy.validation_rules` | object | Yes | Attestation validation criteria |
| `policy.signature` | object | No | Digital signature for integrity |

### Metadata Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Human-readable policy name |
| `version` | string | No | Policy version |
| `description` | string | No | Policy description |
| `created_by` | string | No | Policy creator |
| `created_date` | string | No | Creation date (ISO format) |
| `last_updated` | string | No | Last update date (ISO format) |

### Signature Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `algorithm` | string | Yes | Algorithm used |
| `padding` | string | Yes | Padding (either PSS or PKCS1v15) |
| `value` | string | Yes | Base64 encoded signature |
| `signed_data` | string | No | Specifies which structures were signed, not implemented yet |

### TDX Specific Fields
##### TCB
The `tcb` item within `validation_rules` is a special case for TDX policies. It is used to require specific TCB levels or better for various components, along with an `update` field to require a minimum TCB-R freshness. See the example policy `tdx_example_policy.json` or the excerpt below for an example.

```json
...
  "validation_rules": {
    "tcb": {
      "update": "standard",
      "platform_tcb": "UpToDate",
      "tdx_module_tcb": "UpToDate",
      "qe_tcb": "UpToDate"
    },
...
```

## Signing Policies

### Why Sign Policies?

Policy signing provides:
- **Integrity**: Ensures policy hasn't been tampered with
- **Authentication**: Verifies policy creator
- **Non-repudiation**: Prevents denial of policy authorship

### Step 1: Use TAS Demo Signer

TAS includes a demo signing tool that can generate keys automatically and sign policies. You can use the provided `demo_signer.py` or generate your own keys.

#### Option A: Use Demo Signer with Auto-Generated Keys

```bash
# Navigate to the policy signing directory
cd certs/policy

# Sign your policy (this auto-generates keys if they don't exist)
python3 demo_signer.py /path/to/your-policy.json

# This creates:
# - policy_key.pem (private key with passphrase "passphrase")
# - policy_public_key.pem (public key for TAS configuration)
# - your-policy.json.sig (signature JSON to add to your policy)
```

#### Option B: Generate Your Own Keys

```bash
# Generate your own RSA key pair
openssl genrsa -out my-policy-key.pem 4096

# Generate public key
openssl rsa -in my-policy-key.pem -pubout -out my-policy-public.pem

# Secure the private key
chmod 600 my-policy-key.pem
```

Then modify `demo_signer.py` to use your custom keys, or create your own signing script based on the demo implementation.

### Step 2: Add Signature to Policy

The demo signer creates a separate signature file. You need to manually add the signature to your policy:

```bash
# View the generated signature
cat your-policy.json.sig

# Example output:
# {
#   "signature": {
#     "algorithm": "SHA384",
#     "padding": "PSS", 
#     "value": "base64-encoded-signature...",
#     "signed_data": "validation_rules"
#   }
# }

# Add this signature object to your policy JSON file manually
# or use jq to merge them:
jq -s '.[0] * .[1]' your-policy.json your-policy.json.sig > your-policy-signed.json
```

### Step 3: Configure TAS for Signature Verification

```bash
# Copy all your public keys and certs for policies to the default folder
cp public_key.pem /tas/certs/policy/

# Or alternatively configure TAS to trust your generated public key/cert
export TAS_POLICY_TRUST='/path/to/policy/public_key.pem'
```

### Alternative: Certificate-based Signing

The demo signer can also generate certificates instead of just public keys:

```bash
# Generate certificate instead of public key
python3 demo_signer.py --cert your-policy.json

# This creates:
# - policy_key.pem (private key) 
# - policy_cert.pem (certificate for TAS configuration)
# - your-policy.json.sig (signature JSON)

# Then add the certificate to your configured policy trust directory
```
## Registering Policies

To register a policy with TAS, you must wrap your **signed policy from the previous step** in a registration payload. This payload specifies the policy type and associates it with a secret ID.

### Registration Payload Format

**Important:** The `policy` field contains your complete signed policy from Step 2 above (including metadata, validation_rules, and signature).

```json
{
  "policy_type": "SEV",
  "key_id": "my-secret-id",
  "policy": {
    // This is your complete signed policy from the signing step above
    "metadata": {
      "name": "SEV Production Policy",
      "version": "1.0",
      "description": "Production policy for SEV attestation",
      "created_date": "2024-09-09"
    },
    "validation_rules": {
      "measurement": {
        "exact_match": "a1b2c3d4e5f6789..."
      },
      "policy": {
        "debug_allowed": false,
        "migrate_ma_allowed": false
      }
    },
    "signature": {
      "algorithm": "SHA384",
      "padding": "PSS",
      "value": "base64-encoded-signature..."
    }
  }
}
```

### Registration Payload Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `policy_type` | string | Yes | TEE type: either "SEV" or "TDX" |
| `key_id` | string | Yes | **The secret ID that this policy will be used to release** (must match the secret registered in KMS or HSM) |
| `policy` | object | Yes | **Your complete signed policy from Step 2** (the entire policy JSON including signature) |

**How it works:** When a client requests a secret, TAS uses the policy associated with that secret's `key_id` to validate the attestation evidence before releasing the secret. The `key_id` must exist in the key manager that TAS KBM is connected to.

**Policy Storage Format:** The policy will be stored in Redis using the key format: `policy:{policy_type}:{key_id}`

Example: `policy:SEV:my-secret-id`

### Using curl

```bash
# Set your API key
export TAS_API_KEY="your-api-key-here"

# Register the signed policy
curl -X POST http://localhost:5001/policy/v0/store \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: $TAS_API_KEY" \
  -d  '{
    "policy_type": "SEV",
    "key_id": "...",
    "policy": {
      "metadata": {...},
      "validation_rules": {...},
      "signature": {...}
  }'
  

# Expected response:
# {"message": "Policy 'policy:policy_type:key_id' stored successfully"}
```

## Validation Rule Types

#### exact_match
Requires exact value match:
```json
{
  "measurement": {
    "exact_match": "a1b2c3d4e5f6789abcdef0123456789abcdef"
  }
}
```

#### min_value / max_value
Numeric range validation:
```json
{
  "version": {
    "min_value": 3,
    "max_value": 10
  }
}
```

#### boolean
Boolean flag validation:
```json
{
  "debug": false,
  "migrate_ma": false
}
```

#### allow_list
Check if value is in allowed list:
```json
{
  "processor_family": {
    "allow_list": ["EPYC", "Xeon"]
  }
}
```

#### deny_list
Ensure value is not in banned list:
```json
{
  "algorithms": {
    "deny_list": [4,5]
  }
}
```

## Best Practices

### Security Best Practices

1. **Always Sign Production Policies**
   ```bash
   # Never deploy unsigned policies in production
   export TAS_ENFORCE_SIGNED_POLICIES=true
   ```

2. **Use Strong Key Management**
   ```bash
   # Protect private keys
   chmod 600 policies/keys/*.key
   
   # Use hardware security modules (HSM) for critical keys
   # Store keys separately from policies
   ```

3. **Version Control Policies**
   ```bash
   # Track policy changes
   git add policies/
   git commit -m "Add production SEV policy v1.0"
   git tag policy-v1.0
   ```

## Troubleshooting

### Common Issues

#### Policy Registration Fails
```
Error: Policy signature verification failed
```
**Solutions:**
- Verify the signing key matches the trusted keys in TAS configuration
- Check that the policy was signed correctly
- Ensure TAS is configured with the correct public keys

#### Unsigned Policy Rejected
```
Error: Unsigned policies are not allowed by configuration
```
**Solutions:**
- Sign the policy before registration
- For development, disable enforcement: `export TAS_ENFORCE_SIGNED_POLICIES=false`

#### Invalid Policy Structure
```
Error: Policy must contain 'validation_rules' section
```
**Solutions:**
- Verify all required fields are present
- Check JSON syntax is valid
- Ensure policy follows the correct structure

### Debugging Commands

```bash
# Verify policy syntax
python3 -m json.tool my-policy.json

# List registered policies
curl -H "X-API-KEY: $TAS_API_KEY" http://localhost:5001/policy/v0/list

# Get specific policy
curl -H "X-API-KEY: $TAS_API_KEY" http://localhost:5001/policy/v0/get/policy:SNP:my-policy-id
```
