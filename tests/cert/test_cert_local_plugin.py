#
# TEE Attestation Service - Local Certificate Plugin Tests
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#

import datetime
import logging

import pytest
from asn1crypto import x509 as x509_asn1
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

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


def _reset_local_ca():
    import plugins.tas_cert_local as cert_plugin_module

    cert_plugin_module._ROOT_PRIVATE_KEY = None
    cert_plugin_module._ROOT_CERTIFICATE = None
    cert_plugin_module._INT_PRIVATE_KEY = None
    cert_plugin_module._INT_CERTIFICATE = None


def _persisted_ca_paths(tmp_path):
    return {
        "root_key_file": tmp_path / "root.key",
        "root_cert_file": tmp_path / "root.crt",
        "ca_key_file": tmp_path / "intermediate.key",
        "ca_cert_file": tmp_path / "intermediate.crt",
    }


def _write_persisted_ca_config(tmp_path, paths=None):
    paths = paths or _persisted_ca_paths(tmp_path)
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "ca_trust_domain: example.org\n"
        f"root_key_file: {paths['root_key_file']}\n"
        f"root_cert_file: {paths['root_cert_file']}\n"
        f"ca_key_file: {paths['ca_key_file']}\n"
        f"ca_cert_file: {paths['ca_cert_file']}\n"
    )
    return config_file, paths


def _write_key(path, key):
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _write_cert(path, cert):
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _load_key(path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def _load_cert(path):
    return x509.load_pem_x509_certificate(path.read_bytes())


def _name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _ca_key_usage_ext():
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )


def _root_cert(root_key, not_before, not_after, ca=True, path_length=1):
    root_public_key = root_key.public_key()
    root_name = _name("ca-root.example.org")
    return (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_public_key), False
        )
        .add_extension(_ca_key_usage_ext(), True)
        .sign(root_key, hashes.SHA512())
    )


def _intermediate_cert(
    intermediate_key,
    issuer_key,
    issuer_cert,
    not_before,
    not_after,
    ca=True,
    path_length=0,
):
    intermediate_public_key = intermediate_key.public_key()
    return (
        x509.CertificateBuilder()
        .subject_name(_name("ca.example.org"))
        .issuer_name(issuer_cert.subject)
        .public_key(intermediate_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(intermediate_public_key), False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            False,
        )
        .add_extension(_ca_key_usage_ext(), True)
        .sign(issuer_key, hashes.SHA512())
    )


def test_local_ca_persists_and_reuses_configured_files(tmp_path):
    _reset_local_ca()
    config_file, paths = _write_persisted_ca_config(tmp_path)

    cert_open_client_connection(str(config_file))
    for path in paths.values():
        assert path.is_file()

    root_serial = _load_cert(paths["root_cert_file"]).serial_number
    int_serial = _load_cert(paths["ca_cert_file"]).serial_number

    _reset_local_ca()
    cert_open_client_connection(str(config_file))

    assert _load_cert(paths["root_cert_file"]).serial_number == root_serial
    assert _load_cert(paths["ca_cert_file"]).serial_number == int_serial


def test_local_ca_partial_file_set_raises(tmp_path):
    _reset_local_ca()
    config_file, paths = _write_persisted_ca_config(tmp_path)
    paths["root_key_file"].write_text("partial")

    with pytest.raises(RuntimeError, match="Incomplete local CA file set"):
        cert_open_client_connection(str(config_file))


def test_local_ca_rejects_key_certificate_mismatch(tmp_path):
    _reset_local_ca()
    config_file, paths = _write_persisted_ca_config(tmp_path)
    cert_open_client_connection(str(config_file))

    _reset_local_ca()
    _write_key(paths["ca_key_file"], ec.generate_private_key(ec.SECP384R1()))

    with pytest.raises(RuntimeError, match="private key does not match"):
        cert_open_client_connection(str(config_file))


def test_local_ca_rejects_expired_and_not_yet_valid_certificates(tmp_path):
    _reset_local_ca()
    config_file, paths = _write_persisted_ca_config(tmp_path)
    cert_open_client_connection(str(config_file))

    root_key = _load_key(paths["root_key_file"])
    now = datetime.datetime.now(datetime.timezone.utc)
    expired_root = _root_cert(
        root_key,
        now - datetime.timedelta(days=2),
        now - datetime.timedelta(days=1),
    )
    _write_cert(paths["root_cert_file"], expired_root)

    _reset_local_ca()
    with pytest.raises(RuntimeError, match="expired"):
        cert_open_client_connection(str(config_file))

    future_root = _root_cert(
        root_key,
        now + datetime.timedelta(days=1),
        now + datetime.timedelta(days=2),
    )
    _write_cert(paths["root_cert_file"], future_root)

    _reset_local_ca()
    with pytest.raises(RuntimeError, match="not valid before"):
        cert_open_client_connection(str(config_file))


def test_local_ca_rejects_mismatched_chain(tmp_path):
    _reset_local_ca()
    config_file, paths = _write_persisted_ca_config(tmp_path)
    cert_open_client_connection(str(config_file))

    other_paths = _persisted_ca_paths(tmp_path / "other")
    other_paths["root_key_file"].parent.mkdir()
    other_config, other_paths = _write_persisted_ca_config(
        tmp_path / "other", other_paths
    )
    _reset_local_ca()
    cert_open_client_connection(str(other_config))

    paths["root_key_file"].write_bytes(other_paths["root_key_file"].read_bytes())
    paths["root_cert_file"].write_bytes(other_paths["root_cert_file"].read_bytes())

    _reset_local_ca()
    with pytest.raises(RuntimeError, match="signature is invalid|AKI"):
        cert_open_client_connection(str(config_file))


def test_local_ca_rejects_non_ca_certificate(tmp_path):
    _reset_local_ca()
    config_file, paths = _write_persisted_ca_config(tmp_path)
    cert_open_client_connection(str(config_file))

    root_key = _load_key(paths["root_key_file"])
    root_cert = _load_cert(paths["root_cert_file"])
    intermediate_key = _load_key(paths["ca_key_file"])
    now = datetime.datetime.now(datetime.timezone.utc)
    non_ca = _intermediate_cert(
        intermediate_key,
        root_key,
        root_cert,
        now - datetime.timedelta(minutes=1),
        now + datetime.timedelta(days=1),
        ca=False,
        path_length=None,
    )
    _write_cert(paths["ca_cert_file"], non_ca)

    _reset_local_ca()
    with pytest.raises(RuntimeError, match="not a CA"):
        cert_open_client_connection(str(config_file))


def test_local_ca_warns_on_near_expiry(tmp_path, caplog):
    _reset_local_ca()
    config_file, paths = _write_persisted_ca_config(tmp_path)
    cert_open_client_connection(str(config_file))

    root_key = _load_key(paths["root_key_file"])
    now = datetime.datetime.now(datetime.timezone.utc)
    near_expiry_root = _root_cert(
        root_key,
        now - datetime.timedelta(minutes=1),
        now + datetime.timedelta(days=1),
    )
    _write_cert(paths["root_cert_file"], near_expiry_root)

    _reset_local_ca()
    with caplog.at_level(logging.WARNING):
        cert_open_client_connection(str(config_file))

    assert "Loaded root CA certificate expires" in caplog.text


def test_local_ca_rejects_missing_key_usage(tmp_path):
    _reset_local_ca()
    config_file, paths = _write_persisted_ca_config(tmp_path)
    cert_open_client_connection(str(config_file))

    root_key = _load_key(paths["root_key_file"])
    root_cert = _load_cert(paths["root_cert_file"])
    intermediate_key = _load_key(paths["ca_key_file"])
    now = datetime.datetime.now(datetime.timezone.utc)
    # A valid CA cert (correct key, dates, BasicConstraints, signature) but
    # without a KeyUsage extension must be rejected.
    no_key_usage = (
        x509.CertificateBuilder()
        .subject_name(_name("ca.example.org"))
        .issuer_name(root_cert.subject)
        .public_key(intermediate_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(intermediate_key.public_key()),
            False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            False,
        )
        .sign(root_key, hashes.SHA512())
    )
    _write_cert(paths["ca_cert_file"], no_key_usage)

    _reset_local_ca()
    with pytest.raises(RuntimeError, match="KeyUsage"):
        cert_open_client_connection(str(config_file))


def test_local_ca_creates_lock_file(tmp_path):
    _reset_local_ca()
    config_file, paths = _write_persisted_ca_config(tmp_path)

    cert_open_client_connection(str(config_file))

    lock_path = tmp_path / ".tas_cert_local.lock"
    assert lock_path.exists()
