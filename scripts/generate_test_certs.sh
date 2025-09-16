#!/bin/bash
#
# TEE Attestation Service - Test Certificate Generation Script
#
# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This script generates self-signed certificates for local development and testing.
# It creates a simple CA and uses it to sign server and client certificates.
# The server certificate is created with Subject Alternative Names (SANs) for
# 'localhost' and '127.0.0.1' to prevent SSL verification errors.
# Usage:
#   bash generate_test_certs.sh
# The generated certificates will be placed in the ${CERT_DIR} directory.
# The script will overwrite any existing certificates in that directory.
# Prerequisites:
# - OpenSSL must be installed and available in the system PATH.

set -e

# --- Configuration ---
CERT_DIR="certs/kmipjson/client_server"
DAYS_VALID=3650
PKCS12_PASSWORD="password" # Password for the server's .p12 file

# --- Clean up previous certs ---
echo "Cleaning up old certificates in ${CERT_DIR}..."
rm -rf "${CERT_DIR}"

# --- Create directory structure ---
mkdir -p "${CERT_DIR}/ca"
mkdir -p "${CERT_DIR}/server"
mkdir -p "${CERT_DIR}/owner"

echo "Certificate directory structure created."

# --- Certificate Authority (CA) ---
echo "Generating CA private key and certificate..."
# Create a temporary OpenSSL config file for the CA
cat > "${CERT_DIR}/ca/ca.cnf" <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
C = US
ST = CA
L = Palo Alto
O = Test CA
CN = test.ca.com

[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
EOF

openssl genrsa -out "${CERT_DIR}/ca/ca.key" 4096
openssl req -new -x509 -days ${DAYS_VALID} \
    -key "${CERT_DIR}/ca/ca.key" \
    -out "${CERT_DIR}/ca/ca.crt" \
    -config "${CERT_DIR}/ca/ca.cnf" \
    -extensions v3_ca
echo "CA certificate generated."

# --- Server Certificate (for localhost) ---
echo "Generating server private key and certificate..."
# Create a temporary OpenSSL config file for SANs
cat > "${CERT_DIR}/server/server.cnf" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = CA
L = Palo Alto
O = Test Server
CN = localhost

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

# Generate server key and CSR
openssl genrsa -out "${CERT_DIR}/server/server.key" 2048
openssl req -new -key "${CERT_DIR}/server/server.key" -out "${CERT_DIR}/server/server.csr" -config "${CERT_DIR}/server/server.cnf"

# Sign the server certificate with the CA
openssl x509 -req -in "${CERT_DIR}/server/server.csr" -CA "${CERT_DIR}/ca/ca.crt" -CAkey "${CERT_DIR}/ca/ca.key" -CAcreateserial -out "${CERT_DIR}/server/server.crt" -days ${DAYS_VALID} -extensions v3_req -extfile "${CERT_DIR}/server/server.cnf"
echo "Server certificate generated."

# --- Create PKCS#12 file for the server ---
echo "Creating PKCS#12 file for the server..."
openssl pkcs12 -export -out "${CERT_DIR}/server/server.p12" \
    -inkey "${CERT_DIR}/server/server.key" \
    -in "${CERT_DIR}/server/server.crt" \
    -certfile "${CERT_DIR}/ca/ca.crt" \
    -password "pass:${PKCS12_PASSWORD}"

# --- Client Certificate (for 'owner') ---
echo "Generating client private key and certificate..."
openssl genrsa -out "${CERT_DIR}/owner/owner.client.acme.com.key" 2048
openssl req -new -key "${CERT_DIR}/owner/owner.client.acme.com.key" -out "${CERT_DIR}/owner/owner.client.acme.com.csr" -subj "/C=US/ST=CA/L=Palo Alto/O=ACME Inc/CN=owner.client.acme.com"
echo "Client certificate CSR generated."

# Sign the client certificate with the CA
openssl x509 -req -in "${CERT_DIR}/owner/owner.client.acme.com.csr" -CA "${CERT_DIR}/ca/ca.crt" -CAkey "${CERT_DIR}/ca/ca.key" -CAcreateserial -out "${CERT_DIR}/owner/owner.client.acme.com.crt" -days ${DAYS_VALID}
echo "Client certificate generated."

# --- Clean up temporary files ---
rm "${CERT_DIR}/ca/ca.cnf"
rm "${CERT_DIR}/server/server.cnf"
rm "${CERT_DIR}/server/server.csr"
rm "${CERT_DIR}/owner/owner.client.acme.com.csr"

echo "---"
echo "✅ Test certificates generated successfully in '${CERT_DIR}'."
echo "   - For your KMIP server, use the PKCS#12 file:"
echo "     -> ${CERT_DIR}/server/server.p12"
echo "     -> Password: ${PKCS12_PASSWORD}"
echo "   - Your 'kmip.conf' is already configured for the new client certs and CA."
