#
# TEE Attestation Service - SEV-SNP certificate cache tests
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# Processor-family detection (Milan/Genoa/Turin), the per-chip VCEK and
# per-family CRL cache in Redis, and sev_vm_verify's use of them with the
# built-in AMD ARK/ASK from sev_pytools. The KDS is never contacted.
#

import fnmatch
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
import sev_pytools as sev
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from tas.tas_vm import (
    SEV_CRL_REFRESH_SECONDS,
    sev_fetch_vcek_kds,
    sev_get_crl,
    sev_get_vcek,
    sev_processor_family,
    sev_store_vcek,
    sev_tcb_tag,
    sev_vm_verify,
)

GENOA_HWID = bytes(range(64))
TURIN_HWID = bytes(range(1, 9))  # 8 bytes, zero-padded in the report
POLICY = {"metadata": {"name": "test", "version": "1"}, "validation_rules": {}}


class FakeRedis:
    """The subset of redis.StrictRedis(decode_responses=True) the cache uses."""

    def __init__(self):
        self.strings, self.hashes = {}, {}

    def get(self, key):
        return self.strings.get(key)

    def set(self, key, value):
        self.strings[key] = value

    def delete(self, *keys):
        return sum(
            (self.strings.pop(k, None) is not None)
            + (self.hashes.pop(k, None) is not None)
            for k in keys
        )

    def scan_iter(self, match="*", count=None):
        for key in list(self.strings) + list(self.hashes):
            if fnmatch.fnmatchcase(key, match):
                yield key

    def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    def hset(self, key, mapping):
        self.hashes.setdefault(key, {}).update(mapping)
        return len(mapping)


def _report(
    version=3, family=0x19, model=0x11, hwid=GENOA_HWID, tcb=(9, 0, 23, 72), fmc=None
):
    """Synthetic SNP report: CPUID only for version 3+, FMC-first TCB when fmc is given."""
    b = bytearray(1184)
    b[0] = version
    bl, tee, snp, ucode = tcb
    tcb_bytes = (
        bytes([fmc, bl, tee, snp, 0, 0, 0, ucode])
        if fmc is not None
        else bytes([bl, tee, 0, 0, 0, 0, snp, ucode])
    )
    b[0x38:0x40] = tcb_bytes
    b[0x180:0x188] = tcb_bytes
    if version >= 3:
        b[0x188], b[0x189] = family, model
    b[0x1A0:0x1E0] = hwid.ljust(64, b"\0")
    return sev.AttestationReport.unpack(bytes(b))


def _cert(cn="SEV-VCEK"):
    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA384())
    )


def _crl(next_update):
    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "ARK-Test")])
    return (
        x509.CertificateRevocationListBuilder()
        .issuer_name(name)
        .last_update(datetime.now(timezone.utc) - timedelta(days=2))
        .next_update(next_update)
        .sign(key, hashes.SHA384())
    )


FRESH_CRL = _crl(datetime.now(timezone.utc) + timedelta(days=30))
EXPIRED_CRL = _crl(datetime.now(timezone.utc) - timedelta(days=1))


# --------------------------------------------------------------------------- #
# Processor family
# --------------------------------------------------------------------------- #
def test_tcb_tag():
    assert sev_tcb_tag(_report().reported_tcb) == "9.0.23.72"
    turin = _report(family=0x1A, hwid=TURIN_HWID, tcb=(3, 3, 7, 102), fmc=1)
    assert sev_tcb_tag(turin.reported_tcb) == "1.3.3.7.102"


@pytest.mark.parametrize(
    "family, model, expected",
    [
        (0x19, 0x01, sev.ProcType.MILAN),
        (0x19, 0x11, sev.ProcType.GENOA),
        (0x19, 0xA0, sev.ProcType.BERGAMO),  # Genoa chain and KDS path
        (0x1A, 0x11, sev.ProcType.TURIN),
    ],
)
def test_family_from_cpuid(family, model, expected):
    assert sev_processor_family(_report(family=family, model=model)) is expected


def test_family_of_v2_report_comes_from_the_vcek_issuer_or_is_unknown():
    v2 = _report(version=2)
    assert not v2.supports_cpuid
    assert sev_processor_family(v2) is None
    vcek = _cert()
    with (
        patch(
            "sev_pytools.complete_certificates",
            return_value={"ark": "ark", "vcek": vcek},
        ) as cc,
        patch("sev_pytools.builtin_family_of_ark", return_value="Milan"),
    ):
        assert sev_processor_family(v2, vcek) is sev.ProcType.MILAN
    assert cc.call_args.args[0] == {"vcek": vcek}


# --------------------------------------------------------------------------- #
# VCEK cache
# --------------------------------------------------------------------------- #
def test_vcek_cache_is_per_chip_and_tcb_and_replaces_older_tcbs():
    r = FakeRedis()
    report, vcek = _report(), _cert()
    assert sev_get_vcek(r, report) is None
    sev_store_vcek(r, report, vcek)
    assert sev_get_vcek(r, report) == vcek
    assert list(r.strings) == [f"sev:vcek:{GENOA_HWID.hex()}:9.0.23.72"]

    other_chip = _report(hwid=bytes(64))
    sev_store_vcek(r, other_chip, _cert())
    # firmware update on the first chip: the old TCB's VCEK goes, the other chip's stays
    updated, new_vcek = _report(tcb=(9, 0, 24, 72)), _cert()
    sev_store_vcek(r, updated, new_vcek)
    assert sorted(r.strings) == sorted(
        [
            f"sev:vcek:{GENOA_HWID.hex()}:9.0.24.72",
            f"sev:vcek:{bytes(64).hex()}:9.0.23.72",
        ]
    )
    assert sev_get_vcek(r, report) is None
    assert sev_get_vcek(r, updated) == new_vcek


def test_turin_vcek_key_uses_8_byte_chip_id_and_fmc():
    r = FakeRedis()
    turin = _report(family=0x1A, hwid=TURIN_HWID, tcb=(3, 3, 7, 102), fmc=1)
    sev_store_vcek(r, turin, _cert())
    assert list(r.strings) == [f"sev:vcek:{TURIN_HWID.hex()}:1.3.3.7.102"]


# --------------------------------------------------------------------------- #
# KDS fetch with family probing
# --------------------------------------------------------------------------- #
def test_fetch_vcek_probes_families_for_v2_reports():
    v2, vcek = _report(version=2), _cert()

    def kds(family, report=None):
        if family is sev.ProcType.MILAN:
            return vcek
        raise Exception("Unable to fetch VCEK: HTTP 404")

    with patch("sev_pytools.fetch.request_vcek_kds", side_effect=kds) as m:
        assert sev_fetch_vcek_kds(v2) == (vcek, sev.ProcType.MILAN)
    assert [c.args[0] for c in m.call_args_list] == [
        sev.ProcType.GENOA,
        sev.ProcType.MILAN,
    ]

    with patch("sev_pytools.fetch.request_vcek_kds", return_value=vcek) as m:
        assert sev_fetch_vcek_kds(_report(family=0x1A), sev.ProcType.TURIN) == (
            vcek,
            sev.ProcType.TURIN,
        )
    m.assert_called_once()
    assert m.call_args.args[0] is sev.ProcType.TURIN

    with patch("sev_pytools.fetch.request_vcek_kds", side_effect=Exception("HTTP 404")):
        with pytest.raises(
            RuntimeError, match="Genoa: HTTP 404; Milan: HTTP 404; Turin: HTTP 404"
        ):
            sev_fetch_vcek_kds(v2)


# --------------------------------------------------------------------------- #
# CRL cache
# --------------------------------------------------------------------------- #
def test_crl_is_cached_per_family_and_refreshed():
    r = FakeRedis()
    with patch("sev_pytools.fetch.request_crl_kds", return_value=FRESH_CRL) as kds:
        assert sev_get_crl(r, sev.ProcType.GENOA) == FRESH_CRL
        assert kds.call_args.args == (sev.ProcType.GENOA, sev.Endorsement.VCEK)
        assert set(r.hashes) == {"sev:crl:Genoa"}
        assert sev_get_crl(r, sev.ProcType.GENOA) == FRESH_CRL
        assert sev_get_crl(r, sev.ProcType.BERGAMO) == FRESH_CRL  # Genoa's CRL
        assert kds.call_count == 1
        sev_get_crl(r, sev.ProcType.TURIN)
        assert kds.call_count == 2 and set(r.hashes) == {
            "sev:crl:Genoa",
            "sev:crl:Turin",
        }

        # older than the refresh interval -> fetched again even though still valid
        old = datetime.now(timezone.utc) - timedelta(
            seconds=SEV_CRL_REFRESH_SECONDS + 1
        )
        r.hashes["sev:crl:Genoa"]["fetched_at"] = old.isoformat()
        sev_get_crl(r, sev.ProcType.GENOA)
        assert kds.call_count == 3
        assert r.hashes["sev:crl:Genoa"]["fetched_at"] != old.isoformat()


def test_crl_when_kds_is_down(caplog):
    r = FakeRedis()
    with patch("sev_pytools.fetch.request_crl_kds", side_effect=Exception("offline")):
        with pytest.raises(RuntimeError, match="cache empty"):
            sev_get_crl(r, sev.ProcType.GENOA)
        # stale by refresh interval but still within its validity: used, with a warning
        old = datetime.now(timezone.utc) - timedelta(
            seconds=SEV_CRL_REFRESH_SECONDS + 1
        )
        r.hashes["sev:crl:Genoa"] = {
            "pem": FRESH_CRL.public_bytes(serialization.Encoding.PEM).decode(),
            "fetched_at": old.isoformat(),
        }
        assert sev_get_crl(r, sev.ProcType.GENOA) == FRESH_CRL
        assert "using the cached Genoa CRL" in caplog.text
        # past next_update: never used
        r.hashes["sev:crl:Genoa"]["pem"] = EXPIRED_CRL.public_bytes(
            serialization.Encoding.PEM
        ).decode()
        with pytest.raises(RuntimeError, match="cache expired"):
            sev_get_crl(r, sev.ProcType.GENOA)


# --------------------------------------------------------------------------- #
# sev_vm_verify
# --------------------------------------------------------------------------- #
def test_sev_vm_verify_passes_only_the_vcek_and_the_family_crl():
    r = FakeRedis()
    vcek = _cert()
    turin = _report(family=0x1A, hwid=TURIN_HWID, tcb=(3, 3, 7, 102), fmc=1)
    with (
        patch("sev_pytools.fetch.request_vcek_kds", return_value=vcek) as vcek_kds,
        patch("sev_pytools.fetch.request_crl_kds", return_value=FRESH_CRL) as crl_kds,
        patch(
            "sev_pytools.verify.cert_verify_attestation_report", return_value=True
        ) as cert_verify,
        patch(
            "sev_pytools.verify.policy_verify_attestation_report", return_value=True
        ) as policy_verify,
    ):
        assert sev_vm_verify(r, "nonce", turin.to_bytes(), POLICY) == (True, None)
        assert sev_vm_verify(r, "nonce", turin.to_bytes(), POLICY) == (True, None)
    assert vcek_kds.call_count == 1 and vcek_kds.call_args.args[0] is sev.ProcType.TURIN
    assert crl_kds.call_count == 1 and crl_kds.call_args.args[0] is sev.ProcType.TURIN
    _, certificates, crl = cert_verify.call_args.args
    assert certificates == {"vcek": vcek}  # ARK/ASK come from sev_pytools' built-ins
    assert crl == FRESH_CRL
    assert policy_verify.call_args.args[2] == b"nonce"
    assert set(r.strings) == {f"sev:vcek:{TURIN_HWID.hex()}:1.3.3.7.102"}
    assert set(r.hashes) == {"sev:crl:Turin"}


def test_sev_vm_verify_caches_a_fetched_vcek_only_after_it_verified():
    # e.g. the KDS answered for the chip's hwID under another family (a key that
    # cannot verify this report): the failure must not be cached for the chip
    r = FakeRedis()
    with (
        patch("sev_pytools.fetch.request_vcek_kds", return_value=_cert()),
        patch("sev_pytools.fetch.request_crl_kds", return_value=FRESH_CRL),
        patch(
            "sev_pytools.verify.cert_verify_attestation_report",
            side_effect=ValueError("The attestation report failed verification"),
        ),
        patch("sev_pytools.verify.policy_verify_attestation_report") as policy_verify,
    ):
        ok, error = sev_vm_verify(r, "nonce", _report().to_bytes(), POLICY)
    assert (ok, error) == (
        False,
        "Verification error: The attestation report failed verification",
    )
    assert r.strings == {}  # no VCEK cached
    policy_verify.assert_not_called()


def test_sev_vm_verify_reports_certificate_failures():
    with patch("sev_pytools.fetch.request_vcek_kds", side_effect=Exception("HTTP 503")):
        ok, error = sev_vm_verify(FakeRedis(), "nonce", _report().to_bytes(), POLICY)
    assert ok is False
    assert error.startswith(
        "Verification error: Unable to fetch the VCEK from the AMD KDS"
    )
