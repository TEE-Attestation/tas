#
# TEE Attestation Service - Local Certificate Plugin Tests
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#

import pytest
from asn1crypto import x509 as x509_asn1

from plugins.tas_cert_local import (
    cert_get_ca_info,
    cert_open_client_connection,
    cert_sign,
)


def test_cert_local_plugin():
    # Should open successfully (generate CA)
    client = cert_open_client_connection(None)
    assert client == "ephemeral_local_ca"

    info = cert_get_ca_info(client)
    assert "issuer_dn" in info
    assert "authority_key_identifier" in info
    assert "ca_cert_der" in info
    assert info["signature_suite"]["algorithm"] == "sha512_ecdsa"

    # Just dummy TBS bytes for testing if signature generates without crashing
    tbs_der = b"dummy tbs data to be signed"

    sig = cert_sign(client, tbs_der, info["signature_suite"])
    assert sig is not None
    assert isinstance(sig, bytes)


def test_local_ca_has_spiffe_uri_san_no_path(tmpdir):
    """Validate that local CA cert has SPIFFE URI SAN with trust domain, and CN derived from trust domain."""
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID

    import plugins.tas_cert_local as cert_plugin_module
    from plugins.tas_cert_local import cert_close_client_connection

    # Reset the plugin's global state to get a fresh CA with our config
    cert_plugin_module._ROOT_PRIVATE_KEY = None
    cert_plugin_module._ROOT_CERTIFICATE = None
    cert_plugin_module._INT_PRIVATE_KEY = None
    cert_plugin_module._INT_CERTIFICATE = None

    config_file = tmpdir.join("config.yaml")
    config_file.write("ca_trust_domain: example.org\n")

    client = cert_open_client_connection(str(config_file))
    ca_info = cert_get_ca_info(client)

    # Parse CA cert from DER (this is the intermediate issuing CA)
    ca_cert = x509.load_der_x509_certificate(ca_info["ca_cert_der"])

    # Assert exactly one URI SAN
    san_ext = ca_cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    )
    uri_sans = san_ext.value.get_values_for_type(x509.UniformResourceIdentifier)
    assert len(uri_sans) == 1

    # Assert CA SPIFFE ID format: spiffe://<trust-domain> (no path component)
    ca_spiffe_id = uri_sans[0]
    assert ca_spiffe_id == "spiffe://example.org"
    assert ca_spiffe_id.startswith("spiffe://")
    assert not ca_spiffe_id.endswith("/")
    assert ca_spiffe_id.count("/") == 2  # Only scheme separator

    # Assert CN is derived from trust domain
    cn_attrs = ca_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    assert len(cn_attrs) > 0
    assert cn_attrs[0].value == "ca.example.org"

    # Intermediate is a signing CA constrained to issue only leaves (pathlen=0).
    bc_ext = ca_cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    assert bc_ext.critical is True
    assert bc_ext.value.ca is True
    assert bc_ext.value.path_length == 0

    cert_close_client_connection(client)


def test_local_ca_root_intermediate_hierarchy(tmpdir):
    """Validate the 2-tier root+intermediate CA hierarchy and path-length limits."""
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtensionOID, NameOID

    import plugins.tas_cert_local as cert_plugin_module
    from plugins.tas_cert_local import cert_close_client_connection

    cert_plugin_module._ROOT_PRIVATE_KEY = None
    cert_plugin_module._ROOT_CERTIFICATE = None
    cert_plugin_module._INT_PRIVATE_KEY = None
    cert_plugin_module._INT_CERTIFICATE = None

    config_file = tmpdir.join("config.yaml")
    config_file.write("ca_trust_domain: example.org\n")

    client = cert_open_client_connection(str(config_file))
    ca_info = cert_get_ca_info(client)

    # Chain is ordered leaf->root: [intermediate, root].
    assert len(ca_info["chain"]) == 2
    intermediate = x509.load_pem_x509_certificate(ca_info["chain"][0])
    root = x509.load_pem_x509_certificate(ca_info["chain"][1])

    # Root: self-signed, pathlen=1, critical BasicConstraints.
    root_cn = root.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert root_cn == "ca-root.example.org"
    assert root.subject == root.issuer
    root_bc = root.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
    assert root_bc.critical is True
    assert root_bc.value.ca is True
    assert root_bc.value.path_length == 1
    # Root self-signature verifies with its own public key.
    root.public_key().verify(
        root.signature,
        root.tbs_certificate_bytes,
        ec.ECDSA(root.signature_hash_algorithm),
    )

    # Intermediate: issued by root, pathlen=0, signed by the root key.
    assert intermediate.issuer == root.subject
    int_bc = intermediate.extensions.get_extension_for_oid(
        ExtensionOID.BASIC_CONSTRAINTS
    )
    assert int_bc.value.path_length == 0
    root.public_key().verify(
        intermediate.signature,
        intermediate.tbs_certificate_bytes,
        ec.ECDSA(intermediate.signature_hash_algorithm),
    )
    # Intermediate is NOT self-signed (its signature must fail against its own key).
    with pytest.raises(InvalidSignature):
        intermediate.public_key().verify(
            intermediate.signature,
            intermediate.tbs_certificate_bytes,
            ec.ECDSA(intermediate.signature_hash_algorithm),
        )

    # Both CA certs carry the trust-domain SPIFFE URI SAN.
    for ca in (root, intermediate):
        san = ca.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
        assert uris == ["spiffe://example.org"]

    cert_close_client_connection(client)
