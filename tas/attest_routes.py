#
# TEE Attestation Service - TAS-Attestation Routes
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# Lets a remote verifier obtain the attestation report of the confidential VM
# that TAS itself runs in, through the kernel's vendor-neutral configfs-tsm
# interface. The endpoint does no parsing: the raw report (SEV-SNP attestation
# report, TDX quote, ...) is returned for the verifier to check. It is
# unauthenticated by default (the report is firmware-signed public data) unless
# TAS_ATTEST_REQUIRE_MANAGEMENT_API_KEY is set, in which case the management
# API key applies: the caller is the operator deciding whether to trust TAS.
#
# The report is always bound to the TLS session:
#   REPORT_DATA = SHA-512("TAS-attest/v1" || nonce || SHA-256(TLS leaf certificate DER))
# If the certificate cannot be read the endpoint fails closed (503).
# Routes: POST /attest/v0/report  {"nonce": "<hex, 16-64 bytes>"}
#

import base64
import errno
import fcntl
import hashlib
import math
import os
import time
from contextlib import contextmanager

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from flask import Blueprint, current_app, jsonify, request

from .auth import authenticate_management_request
from .tas_logging import get_logger

logger = get_logger(__name__)

attest_bp = Blueprint("attest", __name__, url_prefix="/attest/v0")

# Report directory provisioned by tas-tsm-slot.service (root creates it and
# chowns inblob to the TAS user; configfs is root-only otherwise).
DEFAULT_TSM_SLOT = "/sys/kernel/config/tsm/report/tas"
# Leaf certificate nginx presents; its digest in REPORT_DATA ties the report to
# the TLS session the verifier is talking over, so a plain proxy cannot relay it.
DEFAULT_TLS_CERT_FILE = "/etc/tas/certs/server.crt"
# The slot is one shared mailbox (inblob write + outblob read must not
# interleave), and it is shared by every TAS process, so the lock is a file lock.
# It must live in a directory only the TAS user can write to (not /tmp, /run/lock).
DEFAULT_LOCK_FILE = "/var/lib/tas/attest.lock"
NONCE_MIN_BYTES = 16
NONCE_MAX_BYTES = 64
# Domain separator: the signed value commits to this protocol and version, so a
# REPORT_DATA produced for any other purpose can never satisfy a TAS verifier.
REPORT_DATA_DOMAIN = b"TAS-attest/v1"
# How long a request waits for the slot before giving up with 503. SEV-SNP reports
# take milliseconds; a TDX quote can take seconds, so callers are told to retry
# rather than piling up server threads behind the lock.
SLOT_WAIT_SECONDS = 5


class SlotBusyError(Exception):
    """Another report is being generated and the wait budget was exhausted."""


def _cfg(key, default):
    return current_app.config.get(key) or default


@contextmanager
def slot_lock(lock_file, timeout):
    """Exclusive inter-process lock on the report slot (flock, polled up to timeout)."""
    lock_dir = os.path.dirname(lock_file)
    if lock_dir:
        os.makedirs(lock_dir, mode=0o700, exist_ok=True)
    # O_NOFOLLOW: a planted symlink must not redirect the lock to another file
    fd = os.open(lock_file, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise SlotBusyError() from None
                time.sleep(0.05)
        yield
    finally:
        os.close(fd)  # releases the lock


def generate_tsm_report(slot, report_data):
    """Generate a report through the configfs-tsm slot (caller holds the slot lock).

    Returns (provider, outblob, auxblob): the kernel provider name (e.g.
    "sev_guest", "tdx_guest"), the raw vendor report, and the raw auxiliary
    blob (SEV-SNP: GHCB certificate table) or None if the provider has none.
    """

    def read(name):
        with open(os.path.join(slot, name), "rb") as f:
            return f.read()

    # configfs commits the write on close; the next outblob read regenerates the report.
    with open(os.path.join(slot, "inblob"), "wb") as f:
        f.write(report_data)
    outblob = read("outblob")
    if not outblob:
        raise OSError(errno.EIO, "TSM returned an empty report")
    auxblob = None
    if os.path.exists(os.path.join(slot, "auxblob")):
        auxblob = read("auxblob") or None
    provider = read("provider").decode().strip()
    return provider, outblob, auxblob


def tls_cert_fingerprint(cert_file):
    """SHA-256 of the DER leaf certificate in a PEM (chain) file, or None if unavailable."""
    try:
        with open(cert_file, "rb") as f:
            leaf = x509.load_pem_x509_certificates(f.read())[0]
    except (OSError, ValueError) as e:
        logger.error(f"TLS certificate {cert_file} unusable: {e}")
        return None
    return hashlib.sha256(leaf.public_bytes(Encoding.DER)).digest()


def compute_report_data(nonce, tls_fp):
    """REPORT_DATA = SHA-512(domain || nonce || SHA-256(TLS leaf cert DER)): the 64 bytes inblob takes."""
    return hashlib.sha512(REPORT_DATA_DOMAIN + nonce + tls_fp).digest()


def _error(status, message, **headers):
    response = jsonify({"error": message})
    response.status_code = status
    for name, value in headers.items():
        response.headers[name.replace("_", "-")] = value
    return response


def _rate_limited(budget):
    retry = str(budget.retry_after())
    return _error(
        429,
        "rate_limit_exceeded",
        Retry_After=retry,
        Cache_Control="no-store",
    )


@attest_bp.route("/report", methods=["POST"])
def attestation_report():
    """Return this CVM's raw attestation report bound to the caller's nonce.

    The management API key is only required when
    TAS_ATTEST_REQUIRE_MANAGEMENT_API_KEY is true. Nothing is parsed here. The
    verifier must check the report's signature chain, that its REPORT_DATA
    equals SHA-512("TAS-attest/v1" || nonce || SHA-256(TLS leaf certificate it
    observed)), and that measurements/policy/TCB meet its expectations of TAS.
    """
    if current_app.config.get("TAS_ATTEST_REQUIRE_MANAGEMENT_API_KEY", False):
        auth_response = authenticate_management_request()
        if auth_response:
            return auth_response

    body = request.get_json(silent=True)
    nonce_hex = body.get("nonce") if isinstance(body, dict) else None
    if not isinstance(nonce_hex, str) or not nonce_hex:
        return _error(400, 'JSON body {"nonce": "<hex, 16-64 bytes>"} is required')
    try:
        nonce = bytes.fromhex(nonce_hex)
    except ValueError:
        return _error(400, "nonce must be a hex string")
    if not NONCE_MIN_BYTES <= len(nonce) <= NONCE_MAX_BYTES:
        return _error(400, f"nonce must be {NONCE_MIN_BYTES}-{NONCE_MAX_BYTES} bytes")

    slot = _cfg("TAS_ATTEST_TSM_SLOT", DEFAULT_TSM_SLOT)
    if not os.path.exists(os.path.join(slot, "inblob")):
        logger.warning(f"Attestation report requested but TSM slot {slot} is absent")
        return _error(501, "TAS is not running in a confidential VM (no TSM slot)")

    tls_fp = tls_cert_fingerprint(
        _cfg("TAS_ATTEST_TLS_CERT_FILE", DEFAULT_TLS_CERT_FILE)
    )
    if tls_fp is None:
        return _error(
            503, "TLS binding unavailable: TAS cannot read its TLS certificate"
        )
    report_data = compute_report_data(nonce, tls_fp)

    budget = current_app.extensions.get("tas_attest_budget")
    if budget is not None and not budget.available():  # cheap pre-check, no lock
        return _rate_limited(budget)

    try:
        with slot_lock(
            _cfg("TAS_ATTEST_LOCK_FILE", DEFAULT_LOCK_FILE), SLOT_WAIT_SECONDS
        ):
            # Authoritative check: serialised by the lock, so a burst cannot overshoot.
            if budget is not None and not budget.available():
                return _rate_limited(budget)
            provider, report, auxblob = generate_tsm_report(slot, report_data)
            if budget is not None:
                budget.consume()
    except SlotBusyError:
        logger.warning("Attestation slot busy; asking the client to retry")
        return _error(
            503,
            "attestation report generation is busy, retry shortly",
            Retry_After=str(math.ceil(SLOT_WAIT_SECONDS)),
        )
    except PermissionError as e:
        hint = (
            " (is tas-tsm-slot.service active?)"
            if e.filename and str(e.filename).startswith(slot)
            else ""
        )
        logger.error(f"Permission denied for {e.filename}{hint}")
        return _error(500, "attestation slot is not accessible")
    except OSError as e:
        logger.error(f"TSM report generation failed: {e}")
        return _error(500, f"failed to obtain attestation report: {e.strerror}")

    logger.info(f"Issued {provider} attestation report to {request.remote_addr}")
    response = jsonify(
        {
            "provider": provider,
            "nonce": nonce.hex(),
            "tls_cert_sha256": tls_fp.hex(),
            "report": base64.b64encode(report).decode(),
            "auxblob": base64.b64encode(auxblob).decode() if auxblob else None,
        }
    )
    response.headers["Cache-Control"] = "no-store"
    return response
