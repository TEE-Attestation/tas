#
# TEE Attestation Service - Local Certificate Plugin
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#

import contextlib
import datetime
import hashlib
import os
import tempfile
from typing import Any, Iterator

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None  # type: ignore[assignment]

import yaml
from asn1crypto import x509 as x509_asn1
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from tas.tas_logging import get_logger

logger = get_logger("tas.plugins.tas_cert_local")

# In-memory singleton state for the 2-tier CA hierarchy:
#   root (self-signed) -> intermediate (issuing CA) -> leaves
_ROOT_PRIVATE_KEY: ec.EllipticCurvePrivateKey | None = None
_ROOT_CERTIFICATE: x509.Certificate | None = None
_INT_PRIVATE_KEY: ec.EllipticCurvePrivateKey | None = None
_INT_CERTIFICATE: x509.Certificate | None = None
_CA_TRUST_DOMAIN = "example.org"
_CA_SUBJECT_CN = f"ca.{_CA_TRUST_DOMAIN}"
_CA_EXPIRY_WARNING_DAYS = 30
_CA_PATH_KEYS = ("root_key_file", "root_cert_file", "ca_key_file", "ca_cert_file")
_CA_LOCK_FILENAME = ".tas_cert_local.lock"


@contextlib.contextmanager
def _ca_file_lock(paths: dict[str, str]) -> Iterator[None]:
    """Guard the check-then-act CA file sequence with an exclusive lock.

    Prevents two concurrently starting TAS processes from racing on
    generate-and-write, which could otherwise produce a partial or
    inconsistent CA file set. Raises if advisory file locking is
    unavailable on the platform.
    """
    lock_dir = os.path.dirname(paths["root_key_file"]) or "."
    os.makedirs(lock_dir, exist_ok=True)
    lock_path = os.path.join(lock_dir, _CA_LOCK_FILENAME)

    if fcntl is None:  # pragma: no cover - non-POSIX platforms
        raise RuntimeError(
            "Advisory file locking is unavailable on this platform; refusing "
            "to initialize persisted local CA files without a cross-process "
            "guard"
        )

    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _ca_key_usage() -> x509.KeyUsage:
    """KeyUsage common to CA certificates (keyCertSign + cRLSign)."""
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


def _aware_utc(value: datetime.datetime) -> datetime.datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=datetime.timezone.utc)
    return value.astimezone(datetime.timezone.utc)


def _not_valid_before(cert: x509.Certificate) -> datetime.datetime:
    if hasattr(cert, "not_valid_before_utc"):
        return cert.not_valid_before_utc
    return _aware_utc(cert.not_valid_before)


def _not_valid_after(cert: x509.Certificate) -> datetime.datetime:
    if hasattr(cert, "not_valid_after_utc"):
        return cert.not_valid_after_utc
    return _aware_utc(cert.not_valid_after)


def _ca_file_paths(cfg: dict[str, Any]) -> dict[str, str] | None:
    paths = {key: cfg.get(key) for key in _CA_PATH_KEYS}
    configured = {key: value for key, value in paths.items() if value}
    if not configured:
        return None
    if len(configured) != len(_CA_PATH_KEYS):
        missing = ", ".join(key for key in _CA_PATH_KEYS if not paths.get(key))
        raise RuntimeError(
            f"Incomplete local CA file configuration; missing: {missing}"
        )
    return {key: str(value) for key, value in paths.items()}


def _generate_ca_hierarchy() -> None:
    global _ROOT_PRIVATE_KEY, _ROOT_CERTIFICATE
    global _INT_PRIVATE_KEY, _INT_CERTIFICATE

    spiffe_san = x509.SubjectAlternativeName(
        [x509.UniformResourceIdentifier(f"spiffe://{_CA_TRUST_DOMAIN}")]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = now + datetime.timedelta(days=365)

    # --- Root CA: self-signed, pathlen=1 (may issue exactly one CA below) ---
    _ROOT_PRIVATE_KEY = ec.generate_private_key(ec.SECP384R1())
    root_public_key = _ROOT_PRIVATE_KEY.public_key()
    root_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, f"ca-root.{_CA_TRUST_DOMAIN}")]
    )
    _ROOT_CERTIFICATE = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(_ca_key_usage(), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_public_key),
            critical=False,
        )
        .add_extension(spiffe_san, critical=False)
        .sign(_ROOT_PRIVATE_KEY, hashes.SHA512())
    )

    # --- Intermediate (issuing) CA: signed by root, pathlen=0 (leaves only) ---
    _INT_PRIVATE_KEY = ec.generate_private_key(ec.SECP384R1())
    int_public_key = _INT_PRIVATE_KEY.public_key()
    int_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _CA_SUBJECT_CN)])
    _INT_CERTIFICATE = (
        x509.CertificateBuilder()
        .subject_name(int_name)
        .issuer_name(root_name)
        .public_key(int_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_ca_key_usage(), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(int_public_key),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_public_key),
            critical=False,
        )
        .add_extension(spiffe_san, critical=False)
        .sign(_ROOT_PRIVATE_KEY, hashes.SHA512())
    )


def _fsync_dir(path: str) -> None:
    """Best-effort fsync of a directory so a rename/create is durable."""
    try:
        dir_fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


def _atomic_write_bytes(path: str, data: bytes, mode: int) -> None:
    """Write bytes to path atomically via a same-directory temp file.

    Readers observe either the previous complete file or the new complete
    file, never a partially written one. The temp file is fsynced before the
    rename, and the parent directory is fsynced afterward (best effort) so the
    replacement survives a crash. The temp file is removed on any failure.
    """
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(
        dir=parent, prefix=f".{os.path.basename(path)}.", suffix=".tmp"
    )
    try:
        os.chmod(tmp_path, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
        _fsync_dir(parent)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


def _write_private_key(path: str, key: ec.EllipticCurvePrivateKey) -> None:
    _atomic_write_bytes(
        path,
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        mode=0o600,
    )


def _write_certificate(path: str, cert: x509.Certificate) -> None:
    _atomic_write_bytes(path, cert.public_bytes(serialization.Encoding.PEM), mode=0o644)


def _write_ca_files(paths: dict[str, str]) -> None:
    if (
        _ROOT_PRIVATE_KEY is None
        or _ROOT_CERTIFICATE is None
        or _INT_PRIVATE_KEY is None
        or _INT_CERTIFICATE is None
    ):
        raise RuntimeError("Local CA is not initialized")

    _write_private_key(paths["root_key_file"], _ROOT_PRIVATE_KEY)
    _write_certificate(paths["root_cert_file"], _ROOT_CERTIFICATE)
    _write_private_key(paths["ca_key_file"], _INT_PRIVATE_KEY)
    _write_certificate(paths["ca_cert_file"], _INT_CERTIFICATE)


def _load_private_key(path: str) -> ec.EllipticCurvePrivateKey:
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise RuntimeError(f"Unsupported CA private key type in {path}; expected EC")
    return key


def _load_certificate(path: str) -> x509.Certificate:
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def _validate_key_certificate_pair(
    label: str, key: ec.EllipticCurvePrivateKey, cert: x509.Certificate
) -> None:
    cert_public_key = cert.public_key()
    if not isinstance(cert_public_key, ec.EllipticCurvePublicKey):
        raise RuntimeError(f"Unsupported {label} CA certificate key type; expected EC")
    if key.public_key().public_numbers() != cert_public_key.public_numbers():
        raise RuntimeError(f"Loaded {label} CA private key does not match certificate")


def _validate_certificate_validity(label: str, cert: x509.Certificate) -> None:
    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = _not_valid_before(cert)
    not_after = _not_valid_after(cert)
    if now < not_before:
        raise RuntimeError(
            f"Loaded {label} CA certificate is not valid before {not_before.isoformat()}"
        )
    if now > not_after:
        raise RuntimeError(
            f"Loaded {label} CA certificate expired at {not_after.isoformat()}"
        )
    warning_threshold = now + datetime.timedelta(days=_CA_EXPIRY_WARNING_DAYS)
    if not_after <= warning_threshold:
        days_remaining = (not_after - now).total_seconds() / 86400
        logger.warning(
            "Loaded %s CA certificate expires in %.1f days at %s",
            label,
            days_remaining,
            not_after.isoformat(),
        )


def _validate_ca_basic_constraints(
    label: str, cert: x509.Certificate, expected_path_length: int | None = None
) -> None:
    try:
        bc_ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound as exc:
        raise RuntimeError(
            f"Loaded {label} CA certificate is missing BasicConstraints"
        ) from exc
    if not bc_ext.value.ca:
        raise RuntimeError(f"Loaded {label} CA certificate is not a CA")
    if (
        expected_path_length is not None
        and bc_ext.value.path_length != expected_path_length
    ):
        raise RuntimeError(
            f"Loaded {label} CA certificate must have path_length={expected_path_length}"
        )
    if (
        label == "root"
        and bc_ext.value.path_length is not None
        and bc_ext.value.path_length < 1
    ):
        raise RuntimeError("Loaded root CA certificate must allow an intermediate CA")


def _validate_ca_key_usage(label: str, cert: x509.Certificate) -> None:
    try:
        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise RuntimeError(
            f"Loaded {label} CA certificate is missing KeyUsage"
        ) from exc
    if not key_usage.key_cert_sign:
        raise RuntimeError(
            f"Loaded {label} CA certificate KeyUsage must include keyCertSign"
        )
    if not key_usage.crl_sign:
        raise RuntimeError(
            f"Loaded {label} CA certificate KeyUsage must include cRLSign"
        )


def _verify_certificate_signature(
    label: str, issuer_cert: x509.Certificate, subject_cert: x509.Certificate
) -> None:
    issuer_public_key = issuer_cert.public_key()
    if not isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
        raise RuntimeError(f"Unsupported {label} issuer key type; expected EC")
    if subject_cert.signature_hash_algorithm is None:
        raise RuntimeError(
            f"Loaded {label} CA certificate signature algorithm is unsupported"
        )
    try:
        issuer_public_key.verify(
            subject_cert.signature,
            subject_cert.tbs_certificate_bytes,
            ec.ECDSA(subject_cert.signature_hash_algorithm),
        )
    except InvalidSignature as exc:
        raise RuntimeError(
            f"Loaded {label} CA certificate signature is invalid"
        ) from exc


def _validate_aki_matches_ski(
    issuer_cert: x509.Certificate, subject_cert: x509.Certificate
) -> None:
    try:
        aki = subject_cert.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        ).value
        ski = issuer_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value
    except x509.ExtensionNotFound:
        return
    if aki.key_identifier and aki.key_identifier != ski.digest:
        raise RuntimeError("Loaded intermediate CA AKI does not match root CA SKI")


def _validate_loaded_ca(
    root_key: ec.EllipticCurvePrivateKey,
    root_cert: x509.Certificate,
    int_key: ec.EllipticCurvePrivateKey,
    int_cert: x509.Certificate,
) -> None:
    _validate_key_certificate_pair("root", root_key, root_cert)
    _validate_key_certificate_pair("intermediate", int_key, int_cert)
    _validate_certificate_validity("root", root_cert)
    _validate_certificate_validity("intermediate", int_cert)
    _validate_ca_basic_constraints("root", root_cert)
    _validate_ca_basic_constraints("intermediate", int_cert, expected_path_length=0)
    _validate_ca_key_usage("root", root_cert)
    _validate_ca_key_usage("intermediate", int_cert)
    if root_cert.subject != root_cert.issuer:
        raise RuntimeError("Loaded root CA certificate is not self-issued")
    if int_cert.issuer != root_cert.subject:
        raise RuntimeError(
            "Loaded intermediate CA certificate issuer does not match root subject"
        )
    _verify_certificate_signature("root", root_cert, root_cert)
    _verify_certificate_signature("intermediate", root_cert, int_cert)
    _validate_aki_matches_ski(root_cert, int_cert)


def _load_ca_files(paths: dict[str, str]) -> None:
    global _ROOT_PRIVATE_KEY, _ROOT_CERTIFICATE
    global _INT_PRIVATE_KEY, _INT_CERTIFICATE

    root_key = _load_private_key(paths["root_key_file"])
    root_cert = _load_certificate(paths["root_cert_file"])
    int_key = _load_private_key(paths["ca_key_file"])
    int_cert = _load_certificate(paths["ca_cert_file"])
    _validate_loaded_ca(root_key, root_cert, int_key, int_cert)
    _ROOT_PRIVATE_KEY = root_key
    _ROOT_CERTIFICATE = root_cert
    _INT_PRIVATE_KEY = int_key
    _INT_CERTIFICATE = int_cert


def cert_open_client_connection(
    config_file: str | None = None, trust_domain: str | None = None
) -> str:
    """Initialize the local root+intermediate CA and return a handle.

    Builds or loads a self-signed root CA (pathlen=1) that signs an intermediate
    issuing CA (pathlen=0). The intermediate is the issuer for all leaf
    certificates.

    Args:
        config_file: Optional YAML config path containing `ca_subject_cn`,
            `ca_trust_domain`, and optional persisted CA file paths.
        trust_domain: Optional trust domain (e.g. from TAS_CERT_TRUST_DOMAIN).
            Takes precedence over the YAML `ca_trust_domain` value when provided.

    Returns:
        A static local client handle identifier.
    """
    global _CA_SUBJECT_CN, _CA_TRUST_DOMAIN

    explicit_cn = False
    cfg: dict[str, Any] = {}

    if config_file:
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                loaded_cfg = yaml.safe_load(f)
        except OSError as exc:
            raise RuntimeError(
                f"Unable to read cert plugin config file {config_file}: {exc}"
            ) from exc
        except yaml.YAMLError as exc:
            raise RuntimeError(
                f"Unable to parse cert plugin config file {config_file}: {exc}"
            ) from exc

        if loaded_cfg is not None and not isinstance(loaded_cfg, dict):
            raise RuntimeError(
                f"Cert plugin config file {config_file} must contain a YAML mapping"
            )
        if isinstance(loaded_cfg, dict):
            cfg = loaded_cfg
            if "ca_trust_domain" in cfg:
                _CA_TRUST_DOMAIN = cfg["ca_trust_domain"]
            if "ca_subject_cn" in cfg:
                _CA_SUBJECT_CN = cfg["ca_subject_cn"]
                explicit_cn = True

    # Flask config (TAS_CERT_TRUST_DOMAIN) is the source of truth and overrides YAML.
    if trust_domain:
        _CA_TRUST_DOMAIN = trust_domain

    # CN derives from the trust domain unless explicitly overridden in YAML.
    if not explicit_cn:
        _CA_SUBJECT_CN = f"ca.{_CA_TRUST_DOMAIN}"

    ca_paths = _ca_file_paths(cfg)

    logger.info("Initializing local root+intermediate CA")
    if config_file:
        logger.info("Loading cert plugin config from: %s", config_file)

    if _INT_PRIVATE_KEY is None:
        if ca_paths:
            with _ca_file_lock(ca_paths):
                # Re-check existence under the lock: another process may have
                # generated the files while we waited to acquire it.
                exists = {key: os.path.exists(path) for key, path in ca_paths.items()}
                if all(exists.values()):
                    _load_ca_files(ca_paths)
                    logger.info(
                        "Loaded local root+intermediate CA from configured files"
                    )
                elif not any(exists.values()):
                    _generate_ca_hierarchy()
                    _write_ca_files(ca_paths)
                    logger.info("Generated and wrote local root+intermediate CA files")
                else:
                    missing = ", ".join(
                        key
                        for key, exists_for_key in exists.items()
                        if not exists_for_key
                    )
                    raise RuntimeError(
                        "Incomplete local CA file set; missing configured files for: "
                        f"{missing}"
                    )
        else:
            _generate_ca_hierarchy()

        logger.info(
            "Local root+intermediate CA initialized with trust domain: %s",
            _CA_TRUST_DOMAIN,
        )

    return "ephemeral_local_ca"


def cert_get_ca_info(client: str) -> dict[str, Any]:
    """Return issuer metadata required by certificate assembly.

    Args:
        client: Plugin client handle returned by `cert_open_client_connection`.

    Returns:
        Dictionary with issuer DN, AKI, CA certificate, chain, and signature suite.

    Raises:
        RuntimeError: If CA state has not been initialized.
    """
    # We don't actually use the client handle, but we keep it in the signature for consistency with other plugins.
    del client

    if _INT_CERTIFICATE is None or _ROOT_CERTIFICATE is None:
        raise RuntimeError("Local CA is not initialized")

    int_der = _INT_CERTIFICATE.public_bytes(serialization.Encoding.DER)

    asn1_cert = x509_asn1.Certificate.load(int_der)
    aki = hashlib.sha1(
        asn1_cert["tbs_certificate"]["subject_public_key_info"]["public_key"].native
    ).digest()

    return {
        "issuer_dn": asn1_cert["tbs_certificate"]["subject"],
        "authority_key_identifier": aki,
        "ca_cert_der": int_der,
        "chain": [
            _INT_CERTIFICATE.public_bytes(serialization.Encoding.PEM),
            _ROOT_CERTIFICATE.public_bytes(serialization.Encoding.PEM),
        ],
        "signature_suite": {"algorithm": "sha512_ecdsa"},
    }


def cert_sign(client: str, tbs_der: bytes, signature_suite: dict[str, Any]) -> bytes:
    """Sign TBS certificate bytes with the local ephemeral CA key.

    Args:
        client: Plugin client handle returned by `cert_open_client_connection`.
        tbs_der: DER-encoded TBS certificate bytes.
        signature_suite: Signature suite descriptor.

    Returns:
        Raw ECDSA signature bytes.

    Raises:
        ValueError: If requested signature algorithm is unsupported.
        RuntimeError: If local CA private key is not initialized.
    """
    del client

    if signature_suite["algorithm"] != "sha512_ecdsa":
        raise ValueError("Unsupported signature suite")

    if _INT_PRIVATE_KEY is None:
        raise RuntimeError("Local CA private key is not initialized")

    return _INT_PRIVATE_KEY.sign(tbs_der, ec.ECDSA(hashes.SHA512()))


def cert_close_client_connection(client: str) -> None:
    """Close plugin client connection.

    Args:
        client: Plugin client handle.

    Returns:
        None.
    """
    del client
