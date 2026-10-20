#
# TEE Attestation Service - Tests for tas_vm verification functions
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#

import base64
import hashlib
import json
from unittest.mock import MagicMock, patch

import pytest

from tas.tas_vm import gpu_vm_verify, verify, vm_verify

# A minimal valid policy JSON for mocking get_policy_from_redis
_MOCK_POLICY = {"metadata": {"key_id": "test-key"}, "validation_rules": {}}

# ── gpu_vm_verify tests ─────────────────────────────────────────────


class TestGpuVmVerify:
    """Tests for the gpu_vm_verify function (nvidia_pytools integration)."""

    EVIDENCE_B64 = base64.b64encode(b"\x01\x02\x03").decode()

    @patch("tas.components.gpu_nvidia.GPU_PYTOOLS_AVAILABLE", False)
    def test_unavailable_returns_install_message(self):
        """When nvidia_pytools is not installed, return an actionable error."""
        from tas.components.gpu_nvidia import gpu_vm_verify as direct_verify

        ok, key_id, err = direct_verify("gpu-nvidia", self.EVIDENCE_B64, 0)
        assert ok is False
        assert key_id is None
        assert "not installed" in err
        assert "0" in err

    @patch("tas.components.gpu_nvidia.nvidia_pytools")
    @patch("tas.components.gpu_nvidia.GPU_PYTOOLS_AVAILABLE", True)
    def test_successful_verification(self, mock_nvidia):
        """Successful nvidia_pytools verification returns (True, claims, None)."""
        from tas.components.gpu_nvidia import gpu_vm_verify as direct_verify

        mock_claims = MagicMock()
        mock_claims.hwmodel = "H100"
        mock_nvidia.verify_gpu_evidence.return_value = (True, mock_claims, None)

        ok, claims, err = direct_verify("gpu-nvidia", self.EVIDENCE_B64, 0)
        assert ok is True
        assert claims is mock_claims
        assert err is None
        mock_nvidia.verify_gpu_evidence.assert_called_once_with(
            gpu_evidence_b64=self.EVIDENCE_B64,
            device_index=0,
            expected_nonce=None,
            policy=None,
            mode="remote",
            collateral=None,
        )

    @patch("tas.components.gpu_nvidia.nvidia_pytools")
    @patch("tas.components.gpu_nvidia.GPU_PYTOOLS_AVAILABLE", True)
    def test_failed_verification_propagates_error(self, mock_nvidia):
        """Failed nvidia_pytools verification propagates the error string."""
        from tas.components.gpu_nvidia import gpu_vm_verify as direct_verify

        mock_nvidia.verify_gpu_evidence.return_value = (
            False,
            None,
            "GPU 0: token signature invalid",
        )

        ok, key_id, err = direct_verify("gpu-nvidia", self.EVIDENCE_B64, 0)
        assert ok is False
        assert key_id is None
        assert "token signature invalid" in err

    @patch("tas.components.gpu_nvidia.nvidia_pytools")
    @patch("tas.components.gpu_nvidia.GPU_PYTOOLS_AVAILABLE", True)
    def test_nonce_passed_to_nvidia_pytools(self, mock_nvidia):
        """expected_nonce should be forwarded to nvidia_pytools."""
        from tas.components.gpu_nvidia import gpu_vm_verify as direct_verify

        mock_nvidia.verify_gpu_evidence.return_value = (True, MagicMock(), None)

        direct_verify("gpu-nvidia", self.EVIDENCE_B64, 2, expected_nonce="abc123")
        mock_nvidia.verify_gpu_evidence.assert_called_once_with(
            gpu_evidence_b64=self.EVIDENCE_B64,
            device_index=2,
            expected_nonce="abc123",
            policy=None,
            mode="remote",
            collateral=None,
        )

    def test_fallback_stub_when_import_fails(self):
        """The fallback stub in tas_vm should mention nvidia_pytools not installed."""
        # gpu_vm_verify imported at module level falls back if import fails;
        # test the actual imported function (may be real or stub depending on env)
        ok, key_id, err = gpu_vm_verify("gpu-nvidia", self.EVIDENCE_B64, 3)
        # Either it works (nvidia_pytools installed) or returns a clear error
        assert isinstance(ok, bool)
        if not ok:
            assert "3" in err or "GPU" in err


# ── vm_verify input validation tests ────────────────────────────────


class TestVmVerifyInputValidation:
    """Tests for vm_verify input validation (before TEE dispatch)."""

    VALID_EVIDENCE_B64 = base64.b64encode(b"\x01\x02\x03").decode()

    def test_empty_nonce_rejected(self):
        ok, _, err = vm_verify(
            MagicMock(), MagicMock(), "", "amd-sev-snp", self.VALID_EVIDENCE_B64, "k1"
        )
        assert ok is False
        assert "Nonce" in err

    def test_none_nonce_rejected(self):
        ok, _, err = vm_verify(
            MagicMock(), MagicMock(), None, "amd-sev-snp", self.VALID_EVIDENCE_B64, "k1"
        )
        assert ok is False
        assert "Nonce" in err

    def test_invalid_tee_type_rejected(self):
        ok, _, err = vm_verify(
            MagicMock(),
            MagicMock(),
            "abc123",
            "bad-type",
            self.VALID_EVIDENCE_B64,
            "k1",
        )
        assert ok is False
        assert "TEE type" in err

    def test_invalid_base64_evidence_rejected(self):
        ok, _, err = vm_verify(
            MagicMock(), MagicMock(), "abc123", "amd-sev-snp", "!!!bad!!!", "k1"
        )
        assert ok is False
        assert "invalid" in err.lower()

    def test_empty_evidence_rejected(self):
        empty_b64 = base64.b64encode(b"").decode()
        ok, _, err = vm_verify(
            MagicMock(), MagicMock(), "abc123", "amd-sev-snp", empty_b64, "k1"
        )
        assert ok is False
        assert "empty" in err.lower()


# ── vm_verify report_data_binding tests ─────────────────────────────


@patch(
    "tas.tas_vm.get_policy",
    return_value=(_MOCK_POLICY, "test-key"),
)
class TestVmVerifyReportDataBinding:
    """Tests for the report_data_binding computation in vm_verify."""

    NONCE = "test-nonce-1234"
    TEE_EVIDENCE_B64 = base64.b64encode(b"\xde\xad\xbe\xef").decode()
    WRAPPING_KEY = b"\x00" * 32
    KEY_ID = "test-key"

    @patch("tas.tas_vm.sev_vm_verify")
    def test_binding_computes_sha512(self, mock_sev, _mock_policy):
        """With report_data_binding=True, expected_report_data should be SHA-512."""
        mock_sev.return_value = (True, None)

        vm_verify(
            MagicMock(),
            MagicMock(),
            self.NONCE,
            "amd-sev-snp",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
            wrapping_key=self.WRAPPING_KEY,
            report_data_binding=True,
        )

        call_kwargs = mock_sev.call_args
        expected = hashlib.sha512(
            self.NONCE.encode("utf-8") + self.WRAPPING_KEY
        ).digest()
        assert call_kwargs.kwargs["expected_report_data"] == expected

    @patch("tas.tas_vm.sev_vm_verify")
    def test_no_binding_uses_nonce(self, mock_sev, _mock_policy):
        """Without binding, expected_report_data should be the raw nonce bytes."""
        mock_sev.return_value = (True, None)

        vm_verify(
            MagicMock(),
            MagicMock(),
            self.NONCE,
            "amd-sev-snp",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
        )

        call_kwargs = mock_sev.call_args
        assert call_kwargs.kwargs["expected_report_data"] == self.NONCE.encode("utf-8")

    @patch("tas.tas_vm.sev_vm_verify")
    def test_binding_false_uses_nonce(self, mock_sev, _mock_policy):
        """report_data_binding=False should use the raw nonce even with wrapping_key."""
        mock_sev.return_value = (True, None)

        vm_verify(
            MagicMock(),
            MagicMock(),
            self.NONCE,
            "amd-sev-snp",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
            wrapping_key=self.WRAPPING_KEY,
            report_data_binding=False,
        )

        call_kwargs = mock_sev.call_args
        assert call_kwargs.kwargs["expected_report_data"] == self.NONCE.encode("utf-8")

    @patch("tas.tas_vm.sev_vm_verify")
    def test_binding_true_no_wrapping_key_uses_nonce(self, mock_sev, _mock_policy):
        """report_data_binding=True without wrapping_key should fall back to nonce."""
        mock_sev.return_value = (True, None)

        vm_verify(
            MagicMock(),
            MagicMock(),
            self.NONCE,
            "amd-sev-snp",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
            wrapping_key=None,
            report_data_binding=True,
        )

        call_kwargs = mock_sev.call_args
        assert call_kwargs.kwargs["expected_report_data"] == self.NONCE.encode("utf-8")

    @patch("tas.tas_vm.tdx_vm_verify")
    def test_binding_dispatches_to_tdx(self, mock_tdx, _mock_policy):
        """Binding should work for intel-tdx as well."""
        mock_tdx.return_value = (True, None)

        vm_verify(
            MagicMock(),
            MagicMock(),
            self.NONCE,
            "intel-tdx",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
            wrapping_key=self.WRAPPING_KEY,
            report_data_binding=True,
        )

        call_kwargs = mock_tdx.call_args
        expected = hashlib.sha512(
            self.NONCE.encode("utf-8") + self.WRAPPING_KEY
        ).digest()
        assert call_kwargs.kwargs["expected_report_data"] == expected


# ── vm_verify return value propagation tests ────────────────────────


@patch(
    "tas.tas_vm.get_policy",
    return_value=(_MOCK_POLICY, "prop-key"),
)
class TestVmVerifyReturnPropagation:
    """Tests that vm_verify correctly returns the result from TEE verifiers."""

    NONCE = "prop-nonce"
    TEE_EVIDENCE_B64 = base64.b64encode(b"\xab\xcd").decode()
    KEY_ID = "prop-key"

    @patch("tas.tas_vm.sev_vm_verify")
    def test_sev_success_propagated(self, mock_sev, _mock_policy):
        """vm_verify should return (True, key_id, None) when sev_vm_verify succeeds."""
        mock_sev.return_value = (True, None)
        ok, key_id, err = vm_verify(
            MagicMock(),
            MagicMock(),
            self.NONCE,
            "amd-sev-snp",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
        )
        assert ok is True
        assert key_id == "prop-key"
        assert err is None

    @patch("tas.tas_vm.sev_vm_verify")
    def test_sev_failure_propagated(self, mock_sev, _mock_policy):
        """vm_verify should return (False, None, error) when sev_vm_verify fails."""
        mock_sev.return_value = (False, "SEV verification failed")
        ok, key_id, err = vm_verify(
            MagicMock(),
            MagicMock(),
            self.NONCE,
            "amd-sev-snp",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
        )
        assert ok is False
        assert key_id is None
        assert err == "SEV verification failed"

    @patch("tas.tas_vm.tdx_vm_verify")
    def test_tdx_success_propagated(self, mock_tdx, _mock_policy):
        """vm_verify should return (True, key_id, None) when tdx_vm_verify succeeds."""
        mock_tdx.return_value = (True, None)
        ok, key_id, err = vm_verify(
            MagicMock(),
            MagicMock(),
            self.NONCE,
            "intel-tdx",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
        )
        assert ok is True
        assert key_id == "prop-key"
        assert err is None

    @patch("tas.tas_vm.tdx_vm_verify")
    def test_tdx_failure_propagated(self, mock_tdx, _mock_policy):
        """vm_verify should return (False, None, error) when tdx_vm_verify fails."""
        mock_tdx.return_value = (False, "TDX verification failed")
        ok, key_id, err = vm_verify(
            MagicMock(),
            MagicMock(),
            self.NONCE,
            "intel-tdx",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
        )
        assert ok is False
        assert key_id is None
        assert err == "TDX verification failed"


# ── vm_verify GPU evidence tests ────────────────────────────────────


@patch(
    "tas.tas_vm.get_policy",
    return_value=(_MOCK_POLICY, "gpu-key"),
)
class TestVmVerifyGpuEvidence:
    """Tests for GPU evidence handling in vm_verify."""

    NONCE = "gpu-test-nonce"
    TEE_EVIDENCE_B64 = base64.b64encode(b"\xca\xfe").decode()
    WRAPPING_KEY = b"\x11" * 16
    KEY_ID = "gpu-key"
    GPU_EVIDENCE_RAW = b"\xaa\xbb\xcc"

    @staticmethod
    def _make_envelope(raw_bytes):
        """Build a GPU evidence envelope: base64(json({"evidence": base64(raw)}))."""
        inner_b64 = base64.b64encode(raw_bytes).decode()
        envelope = json.dumps({"evidence": inner_b64})
        return base64.b64encode(envelope.encode()).decode()

    @property
    def GPU_EVIDENCE_B64(self):
        return self._make_envelope(self.GPU_EVIDENCE_RAW)

    def test_gpu_evidence_too_many_rejected(self, _mock_policy):
        """More than 16 GPU entries should be rejected."""
        gpu_evidence = [
            {
                "type": "gpu-nvidia",
                "evidence": self.GPU_EVIDENCE_B64,
                "device-index": i,
            }
            for i in range(17)
        ]
        ok, _, err = vm_verify(
            MagicMock(),
            MagicMock(),
            self.NONCE,
            "amd-sev-snp",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
            wrapping_key=self.WRAPPING_KEY,
            report_data_binding=True,
            gpu_list=gpu_evidence,
        )
        assert ok is False
        assert "max 16" in err

    def test_gpu_evidence_exactly_16_passes_cap(self, _mock_policy):
        """Exactly 16 GPU entries should not be rejected by the cap."""
        gpu_evidence = [
            {
                "type": "gpu-nvidia",
                "evidence": self.GPU_EVIDENCE_B64,
                "device-index": i,
            }
            for i in range(16)
        ]
        ok, _, err = vm_verify(
            MagicMock(),
            MagicMock(),
            self.NONCE,
            "amd-sev-snp",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
            wrapping_key=self.WRAPPING_KEY,
            report_data_binding=True,
            gpu_list=gpu_evidence,
        )
        assert ok is False
        # Error should be from gpu_vm_verify stub, not the cap
        assert "max 16" not in err

    def test_gpu_failure_stops_verification(self, _mock_policy):
        """If a GPU fails verification, vm_verify should return its error."""
        gpu_evidence = [
            {
                "type": "gpu-nvidia",
                "evidence": self.GPU_EVIDENCE_B64,
                "device-index": 0,
            },
        ]
        ok, _, err = vm_verify(
            MagicMock(),
            MagicMock(),
            self.NONCE,
            "amd-sev-snp",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
            wrapping_key=self.WRAPPING_KEY,
            report_data_binding=True,
            gpu_list=gpu_evidence,
        )
        assert ok is False
        assert err is not None and "GPU" in err

    @patch("tas.tas_vm.gpu_vm_verify", return_value=(True, None, None))
    @patch("tas.tas_vm.sev_vm_verify")
    def test_gpu_hashes_included_in_binding(self, mock_sev, mock_gpu, _mock_policy):
        """GPU evidence SHA-512 hashes should be included in the binding."""
        mock_sev.return_value = (True, None)

        gpu0_raw = b"\xaa\xbb"
        gpu1_raw = b"\xcc\xdd"
        gpu_evidence = [
            {
                "type": "gpu-nvidia",
                "evidence": self._make_envelope(gpu1_raw),
                "device-index": 1,
            },
            {
                "type": "gpu-nvidia",
                "evidence": self._make_envelope(gpu0_raw),
                "device-index": 0,
            },
        ]

        vm_verify(
            MagicMock(),
            MagicMock(),
            self.NONCE,
            "amd-sev-snp",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
            wrapping_key=self.WRAPPING_KEY,
            report_data_binding=True,
            gpu_list=gpu_evidence,
        )

        # Build expected hash: sorted by device-index (0 first, then 1)
        hash_input = self.NONCE.encode("utf-8") + self.WRAPPING_KEY
        hash_input += hashlib.sha512(gpu0_raw).digest()
        hash_input += hashlib.sha512(gpu1_raw).digest()
        expected = hashlib.sha512(hash_input).digest()

        call_kwargs = mock_sev.call_args
        assert call_kwargs.kwargs["expected_report_data"] == expected

    @patch("tas.tas_vm.gpu_vm_verify", return_value=(True, None, None))
    @patch("tas.tas_vm.sev_vm_verify")
    def test_gpu_evidence_sorted_by_device_index(
        self, mock_sev, mock_gpu, _mock_policy
    ):
        """GPU evidence should be sorted by device-index for deterministic hashing."""
        mock_sev.return_value = (True, None)

        gpu_entries = [
            {
                "type": "gpu-nvidia",
                "evidence": self._make_envelope(b"gpu2"),
                "device-index": 2,
            },
            {
                "type": "gpu-nvidia",
                "evidence": self._make_envelope(b"gpu0"),
                "device-index": 0,
            },
            {
                "type": "gpu-nvidia",
                "evidence": self._make_envelope(b"gpu1"),
                "device-index": 1,
            },
        ]

        vm_verify(
            MagicMock(),
            MagicMock(),
            self.NONCE,
            "amd-sev-snp",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
            wrapping_key=self.WRAPPING_KEY,
            report_data_binding=True,
            gpu_list=gpu_entries,
        )

        # gpu_vm_verify should have been called in sorted order: 0, 1, 2
        calls = mock_gpu.call_args_list
        device_indices = [c.args[2] for c in calls]
        assert device_indices == [0, 1, 2]

    def test_gpu_evidence_without_binding_ignored(self, _mock_policy):
        """GPU evidence without report_data_binding should not trigger GPU verify."""
        gpu_evidence = [
            {
                "type": "gpu-nvidia",
                "evidence": self.GPU_EVIDENCE_B64,
                "device-index": 0,
            },
        ]
        with (
            patch("tas.tas_vm.sev_vm_verify") as mock_sev,
            patch("tas.tas_vm.gpu_vm_verify") as mock_gpu,
        ):
            mock_sev.return_value = (True, None)

            vm_verify(
                MagicMock(),
                MagicMock(),
                self.NONCE,
                "amd-sev-snp",
                self.TEE_EVIDENCE_B64,
                self.KEY_ID,
                wrapping_key=self.WRAPPING_KEY,
                report_data_binding=False,
                gpu_list=gpu_evidence,
            )

            mock_gpu.assert_not_called()

    @patch("tas.tas_vm.gpu_vm_verify", return_value=(True, None, None))
    @patch("tas.tas_vm.sev_vm_verify")
    def test_binding_without_gpu_evidence_no_gpu_verify(
        self, mock_sev, mock_gpu, _mock_policy
    ):
        """Binding without gpu_evidence should not call gpu_vm_verify."""
        mock_sev.return_value = (True, None)

        vm_verify(
            MagicMock(),
            MagicMock(),
            self.NONCE,
            "amd-sev-snp",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
            wrapping_key=self.WRAPPING_KEY,
            report_data_binding=True,
            gpu_list=None,
        )

        mock_gpu.assert_not_called()

        # expected_report_data should be SHA-512(nonce || wrapping_key) with no GPU hashes
        expected = hashlib.sha512(
            self.NONCE.encode("utf-8") + self.WRAPPING_KEY
        ).digest()
        call_kwargs = mock_sev.call_args
        assert call_kwargs.kwargs["expected_report_data"] == expected

    @patch("tas.tas_vm.gpu_vm_verify")
    @patch("tas.tas_vm.sev_vm_verify")
    def test_second_gpu_failure_after_first_passes(
        self, mock_sev, mock_gpu, _mock_policy
    ):
        """If the second GPU fails, its error should be returned."""
        mock_gpu.side_effect = [
            (True, None, None),  # GPU 0 passes
            (False, None, "GPU 1 attestation invalid"),  # GPU 1 fails
        ]

        gpu_evidence = [
            {
                "type": "gpu-nvidia",
                "evidence": self._make_envelope(b"g0"),
                "device-index": 0,
            },
            {
                "type": "gpu-nvidia",
                "evidence": self._make_envelope(b"g1"),
                "device-index": 1,
            },
        ]

        ok, _, err = vm_verify(
            MagicMock(),
            MagicMock(),
            self.NONCE,
            "amd-sev-snp",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
            wrapping_key=self.WRAPPING_KEY,
            report_data_binding=True,
            gpu_list=gpu_evidence,
        )

        assert ok is False
        assert "GPU 1" in err


# ── GPU evidence list shape validation tests ────────────────────────


class _Absent:
    """Sentinel: remove this key from a test entry."""

    def __repr__(self):
        return "<absent>"


_ABSENT = _Absent()


class TestGpuEvidenceListValidation:
    """Tests for _validate_gpu_list and its wiring into the verification paths.

    Regression tests: the GPU evidence list was previously indexed into
    (``len``, ``sorted(key=lambda e: e["device-index"])``) straight from the
    request body, so a non-list or a malformed entry raised an unhandled
    ``TypeError``/``KeyError`` (an HTTP 500), while out-of-range, boolean,
    float or duplicate ``device-index`` values were silently accepted.
    """

    NONCE = "gpu-shape-nonce"
    TEE_EVIDENCE_B64 = base64.b64encode(b"\xca\xfe").decode()
    WRAPPING_KEY = b"\x33" * 16
    KEY_ID = "gpu-shape-key"

    @staticmethod
    def _make_envelope(raw_bytes):
        inner_b64 = base64.b64encode(raw_bytes).decode()
        envelope = json.dumps({"evidence": inner_b64})
        return base64.b64encode(envelope.encode()).decode()

    def _entry(self, **overrides):
        entry = {
            "type": "gpu-nvidia",
            "evidence": self._make_envelope(b"\x01"),
            "device-index": 0,
        }
        entry.update(overrides)
        for key, value in overrides.items():
            if value is _ABSENT:
                del entry[key]
        return entry

    # -- _validate_gpu_list directly --------------------------------------

    def test_well_formed_list_passes(self):
        from tas.tas_vm import _validate_gpu_list

        gpu_list = [self._entry(**{"device-index": i}) for i in range(3)]
        assert _validate_gpu_list(gpu_list) is None

    def test_empty_list_passes(self):
        from tas.tas_vm import _validate_gpu_list

        assert _validate_gpu_list([]) is None

    def test_non_list_rejected(self):
        from tas.tas_vm import _validate_gpu_list

        for bad in [1, True, "x", {"0": {}}, {"device-index": 0}, 1.5, b"x"]:
            err = _validate_gpu_list(bad)
            assert err == "GPU evidence must be a list", f"{bad!r} not rejected"

    def test_too_many_entries_rejected(self):
        """Without an app context the default cap applies."""
        from tas.tas_vm import DEFAULT_MAX_GPU_EVIDENCE_ENTRIES, _validate_gpu_list

        gpu_list = [
            self._entry(**{"device-index": i})
            for i in range(DEFAULT_MAX_GPU_EVIDENCE_ENTRIES + 1)
        ]
        err = _validate_gpu_list(gpu_list)
        assert err == (
            f"Too many GPU evidence entries (max {DEFAULT_MAX_GPU_EVIDENCE_ENTRIES})"
        )

    def test_max_entries_parameter_overrides_default(self):
        from tas.tas_vm import _validate_gpu_list

        gpu_list = [self._entry(**{"device-index": i}) for i in range(3)]
        assert _validate_gpu_list(gpu_list, max_entries=3) is None
        assert _validate_gpu_list(gpu_list, max_entries=2) == (
            "Too many GPU evidence entries (max 2)"
        )

    def test_max_entries_read_from_app_config(self):
        """TAS_GPU_MAX_EVIDENCE_ENTRIES raises or lowers the cap at runtime."""
        from flask import Flask

        from tas.tas_vm import _validate_gpu_list

        gpu_list = [self._entry(**{"device-index": i}) for i in range(20)]

        app = Flask(__name__)
        app.config["TAS_GPU_MAX_EVIDENCE_ENTRIES"] = 32
        with app.app_context():
            assert _validate_gpu_list(gpu_list) is None

        app.config["TAS_GPU_MAX_EVIDENCE_ENTRIES"] = 8
        with app.app_context():
            assert _validate_gpu_list(gpu_list) == (
                "Too many GPU evidence entries (max 8)"
            )

    def test_max_entries_defaults_when_not_configured_in_app(self):
        from flask import Flask

        from tas.tas_vm import DEFAULT_MAX_GPU_EVIDENCE_ENTRIES, _validate_gpu_list

        gpu_list = [
            self._entry(**{"device-index": i})
            for i in range(DEFAULT_MAX_GPU_EVIDENCE_ENTRIES + 1)
        ]
        with Flask(__name__).app_context():
            assert _validate_gpu_list(gpu_list) == (
                f"Too many GPU evidence entries (max {DEFAULT_MAX_GPU_EVIDENCE_ENTRIES})"
            )

    def test_non_object_entries_rejected(self):
        from tas.tas_vm import _validate_gpu_list

        for bad in [None, "not-a-dict", 1, True, [], ["device-index"]]:
            err = _validate_gpu_list([self._entry(), bad])
            assert err == "GPU evidence entry 1 must be an object", f"{bad!r}"

    def test_missing_device_index_rejected(self):
        from tas.tas_vm import _validate_gpu_list

        err = _validate_gpu_list([self._entry(**{"device-index": _ABSENT})])
        assert err == "GPU evidence entry 0: missing or invalid device-index"

    def test_invalid_device_index_values_rejected(self):
        from tas.tas_vm import _validate_gpu_list

        for bad in [-1, True, False, 1.5, "0", None, [0], {}]:
            err = _validate_gpu_list([self._entry(**{"device-index": bad})])
            assert (
                err == "GPU evidence entry 0: missing or invalid device-index"
            ), f"device-index {bad!r} not rejected"

    def test_duplicate_device_index_rejected(self):
        from tas.tas_vm import _validate_gpu_list

        gpu_list = [
            self._entry(**{"device-index": 0}),
            self._entry(**{"device-index": 1}),
            self._entry(**{"device-index": 0}),
        ]
        err = _validate_gpu_list(gpu_list)
        assert err == "GPU evidence entry 2: duplicate device-index"

    def test_contiguous_indices_in_any_order_allowed(self):
        """Indices must cover 0..N-1 but may appear in any order."""
        from tas.tas_vm import _validate_gpu_list

        gpu_list = [self._entry(**{"device-index": i}) for i in (2, 0, 1)]
        assert _validate_gpu_list(gpu_list) is None

    def test_non_contiguous_indices_rejected(self):
        """Gaps or an offset start are rejected even when indices are unique."""
        from tas.tas_vm import _validate_gpu_list

        for indices in [(1,), (0, 2), (3, 0, 7), (1, 2, 3), (0, 1, 3)]:
            gpu_list = [self._entry(**{"device-index": i}) for i in indices]
            err = _validate_gpu_list(gpu_list)
            assert (
                err == "GPU evidence device-index values must be contiguous from 0"
            ), f"indices {indices} not rejected"

    def test_duplicate_reported_before_contiguity(self):
        """A duplicate gets its specific message, not the generic contiguity one."""
        from tas.tas_vm import _validate_gpu_list

        gpu_list = [self._entry(**{"device-index": i}) for i in (0, 0)]
        assert _validate_gpu_list(gpu_list) == (
            "GPU evidence entry 1: duplicate device-index"
        )

    def test_unsupported_type_rejected(self):
        from tas.tas_vm import _validate_gpu_list

        for bad in ["GPU-NVIDIA", "nvidia", "", None, 1, _ABSENT]:
            err = _validate_gpu_list([self._entry(type=bad)])
            assert err == "GPU 0: unsupported GPU device type", f"type {bad!r}"

    def test_missing_or_invalid_evidence_rejected(self):
        from tas.tas_vm import _validate_gpu_list

        for bad in ["", None, 1, True, [], {}, b"abc", _ABSENT]:
            err = _validate_gpu_list([self._entry(evidence=bad)])
            assert err == "GPU 0: missing or invalid evidence", f"evidence {bad!r}"

    def test_error_messages_do_not_echo_client_values(self):
        """Client-facing errors must not reflect attacker-controlled strings."""
        from tas.tas_vm import _validate_gpu_list

        marker = "<script>injected</script>"
        for gpu_list in [
            marker,
            [marker],
            [self._entry(type=marker)],
            [self._entry(evidence=marker, type=marker)],
            [self._entry(**{"device-index": marker})],
        ]:
            err = _validate_gpu_list(gpu_list)
            assert err is not None
            assert marker not in err

    # -- _verify_gpu_evidence_list no longer raises ------------------------

    @patch("tas.tas_vm.gpu_vm_verify")
    def test_verify_gpu_evidence_list_rejects_without_raising(self, mock_gpu):
        from tas.tas_vm import _verify_gpu_evidence_list

        cases = [
            1,
            True,
            "x",
            {"0": {}},
            [None],
            ["not-a-dict"],
            [self._entry(**{"device-index": _ABSENT})],
            [self._entry(**{"device-index": "0"}), self._entry(**{"device-index": 1})],
            [self._entry(**{"device-index": 0}), self._entry(**{"device-index": 0})],
        ]
        for gpu_list in cases:
            ok, err, results = _verify_gpu_evidence_list(MagicMock(), gpu_list, "n")
            assert ok is False, f"{gpu_list!r} accepted"
            assert isinstance(err, str) and err
            assert results is None
        mock_gpu.assert_not_called()

    # -- wiring into verify() / vm_verify() --------------------------------

    @patch("tas.tas_vm.get_policy", return_value=(_MOCK_POLICY, "k"))
    @patch("tas.tas_vm.gpu_vm_verify")
    @patch("tas.tas_vm.sev_vm_verify")
    def test_vm_verify_rejects_malformed_gpu_list(
        self, mock_sev, mock_gpu, _mock_policy
    ):
        """Malformed GPU input fails verification cleanly before any TEE work."""
        for gpu_list in [
            1,
            "x",
            {"0": {}},
            [None],
            [self._entry(**{"device-index": -1})],
        ]:
            ok, key_id, err = vm_verify(
                MagicMock(),
                MagicMock(),
                self.NONCE,
                "amd-sev-snp",
                self.TEE_EVIDENCE_B64,
                self.KEY_ID,
                wrapping_key=self.WRAPPING_KEY,
                report_data_binding=True,
                gpu_list=gpu_list,
            )
            assert ok is False, f"{gpu_list!r} accepted"
            assert key_id is None
            assert err
        mock_gpu.assert_not_called()
        mock_sev.assert_not_called()

    @patch("tas.tas_vm.get_policy", return_value=(_MOCK_POLICY, "k"))
    @patch("tas.tas_vm.gpu_vm_verify")
    @patch("tas.tas_vm.sev_vm_verify")
    def test_vm_verify_rejects_malformed_gpu_list_even_without_binding(
        self, mock_sev, mock_gpu, _mock_policy
    ):
        """Shape validation applies regardless of report_data_binding."""
        ok, _, err = vm_verify(
            MagicMock(),
            MagicMock(),
            self.NONCE,
            "amd-sev-snp",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
            wrapping_key=self.WRAPPING_KEY,
            report_data_binding=False,
            gpu_list={"0": {}},
        )
        assert ok is False
        assert err == "GPU evidence must be a list"
        mock_sev.assert_not_called()

    @patch("tas.tas_vm.get_policy", return_value=(_MOCK_POLICY, "k"))
    @patch("tas.tas_vm.gpu_vm_verify")
    @patch("tas.tas_vm.sev_vm_verify")
    def test_vm_verify_gpu_list_none_still_means_no_gpus(
        self, mock_sev, mock_gpu, _mock_policy
    ):
        mock_sev.return_value = (True, None)
        ok, _, err = vm_verify(
            MagicMock(),
            MagicMock(),
            self.NONCE,
            "amd-sev-snp",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
            wrapping_key=self.WRAPPING_KEY,
            report_data_binding=True,
            gpu_list=None,
        )
        assert ok is True
        assert err is None
        mock_gpu.assert_not_called()


# ── vm_verify GPU policy tests ──────────────────────────────────────

# Example NVIDIA GPU policy (as stored in components.gpu.nvidia)
_NVIDIA_GPU_POLICY = {
    "version": "4.0",
    "authorization-rules": {
        "type": "JWT",
        "overall-claims": {
            "x-nvidia-overall-att-result": True,
        },
        "detached-claims": {
            "measres": "success",
            "dbgstat": "disabled",
        },
    },
}

# A policy with the components.gpu section keyed by device type
_POLICY_WITH_GPU = {
    "metadata": {"key_id": "gpu-test-key"},
    "validation_rules": {},
    "components": {
        "gpu": {
            "gpu-nvidia": _NVIDIA_GPU_POLICY,
        }
    },
}

# A policy without any components section
_POLICY_NO_COMPONENTS = {
    "metadata": {"key_id": "no-gpu-key"},
    "validation_rules": {},
}


class TestVmVerifyGpuPolicy:
    """Tests for GPU component policy extraction and application in vm_verify."""

    NONCE = "gpu-policy-nonce"
    TEE_EVIDENCE_B64 = base64.b64encode(b"\xca\xfe").decode()
    WRAPPING_KEY = b"\x22" * 16
    KEY_ID = "gpu-policy-key"

    @staticmethod
    def _make_envelope(raw_bytes):
        inner_b64 = base64.b64encode(raw_bytes).decode()
        envelope = json.dumps({"evidence": inner_b64})
        return base64.b64encode(envelope.encode()).decode()

    @patch(
        "tas.tas_vm.get_policy",
        return_value=(_POLICY_WITH_GPU, "gpu-test-key"),
    )
    def test_gpu_required_by_policy_but_no_evidence_fails(self, _mock_policy):
        """If policy has components.gpu but no GPU evidence provided, fail."""
        ok, _, err = vm_verify(
            MagicMock(),
            MagicMock(),
            self.NONCE,
            "amd-sev-snp",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
            wrapping_key=self.WRAPPING_KEY,
            report_data_binding=True,
            gpu_list=None,
        )
        assert ok is False
        assert "requires GPU attestation" in err

    @patch(
        "tas.tas_vm.get_policy",
        return_value=(_POLICY_NO_COMPONENTS, "no-gpu-key"),
    )
    @patch("tas.tas_vm.sev_vm_verify")
    def test_gpu_evidence_without_policy_warns_but_passes(self, mock_sev, _mock_policy):
        """GPU evidence without components.gpu in policy logs warning, still verifies."""
        mock_sev.return_value = (True, None)
        gpu_evidence = [
            {
                "type": "gpu-nvidia",
                "evidence": self._make_envelope(b"\xaa"),
                "device-index": 0,
            },
        ]

        # GPU verify will be called without policy (None), should still work
        with patch("tas.tas_vm.gpu_vm_verify", return_value=(True, None, None)):
            ok, key_id, err = vm_verify(
                MagicMock(),
                MagicMock(),
                self.NONCE,
                "amd-sev-snp",
                self.TEE_EVIDENCE_B64,
                self.KEY_ID,
                wrapping_key=self.WRAPPING_KEY,
                report_data_binding=True,
                gpu_list=gpu_evidence,
            )
        assert ok is True
        assert err is None

    @patch(
        "tas.tas_vm.get_policy",
        return_value=(_POLICY_WITH_GPU, "gpu-test-key"),
    )
    @patch("tas.tas_vm.gpu_validate_claims", return_value=(True, None))
    @patch("tas.tas_vm.gpu_vm_verify", return_value=(True, MagicMock(), None))
    @patch("tas.tas_vm.sev_vm_verify")
    def test_nvidia_policy_applied_to_gpu_claims(
        self, mock_sev, mock_gpu, mock_validate, _mock_policy
    ):
        """The NVIDIA policy should be applied to the verified GPU claims."""
        mock_sev.return_value = (True, None)

        gpu_evidence = [
            {
                "type": "gpu-nvidia",
                "evidence": self._make_envelope(b"\xbb"),
                "device-index": 0,
            },
        ]

        vm_verify(
            MagicMock(),
            MagicMock(),
            self.NONCE,
            "amd-sev-snp",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
            wrapping_key=self.WRAPPING_KEY,
            report_data_binding=True,
            gpu_list=gpu_evidence,
        )

        # Evidence is verified without a policy; the policy is applied to the
        # resulting claims instead.
        assert mock_gpu.call_args.kwargs["gpu_policy"] is None
        assert mock_validate.call_args.args[0] == _NVIDIA_GPU_POLICY

    @patch(
        "tas.tas_vm.get_policy",
        return_value=(_POLICY_WITH_GPU, "gpu-test-key"),
    )
    @patch("tas.tas_vm.gpu_validate_claims", return_value=(True, None))
    @patch("tas.tas_vm.gpu_vm_verify", return_value=(True, MagicMock(), None))
    @patch("tas.tas_vm.sev_vm_verify")
    def test_unsupported_device_type_rejected_before_verification(
        self, mock_sev, mock_gpu, mock_validate, _mock_policy
    ):
        """An unknown GPU device type is rejected without verifying or applying policy.

        Regression test: a client could previously present any ``type`` string
        (e.g. a case variant of ``gpu-nvidia``); the evidence was still verified
        by the NVIDIA verifier, but the unmatched type fell outside every
        ``components.gpu`` rule and the policy claims check was skipped.
        """
        mock_sev.return_value = (True, None)

        for bad_type in ["GPU-NVIDIA", "nvidia", "amd-gpu", "spoofed", "", None]:
            gpu_evidence = [
                {
                    "type": bad_type,
                    "evidence": self._make_envelope(b"\xcc"),
                    "device-index": 0,
                },
            ]

            ok, key_id, err = vm_verify(
                MagicMock(),
                MagicMock(),
                self.NONCE,
                "amd-sev-snp",
                self.TEE_EVIDENCE_B64,
                self.KEY_ID,
                wrapping_key=self.WRAPPING_KEY,
                report_data_binding=True,
                gpu_list=gpu_evidence,
            )

            assert ok is False, f"type {bad_type!r} was accepted"
            assert key_id is None
            assert err == "GPU 0: unsupported GPU device type"
            mock_gpu.assert_not_called()
            mock_validate.assert_not_called()
            mock_sev.assert_not_called()

    @patch(
        "tas.tas_vm.get_policy",
        return_value=(_POLICY_WITH_GPU, "gpu-test-key"),
    )
    @patch("tas.tas_vm.gpu_validate_claims", return_value=(True, None))
    @patch("tas.tas_vm.gpu_vm_verify", return_value=(True, MagicMock(), None))
    @patch("tas.tas_vm.sev_vm_verify")
    def test_missing_device_type_rejected(
        self, mock_sev, mock_gpu, mock_validate, _mock_policy
    ):
        """``type`` is required; an entry without it must not default to a known type."""
        mock_sev.return_value = (True, None)

        gpu_evidence = [
            {"evidence": self._make_envelope(b"\xcc"), "device-index": 0},
        ]

        ok, _, err = vm_verify(
            MagicMock(),
            MagicMock(),
            self.NONCE,
            "amd-sev-snp",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
            wrapping_key=self.WRAPPING_KEY,
            report_data_binding=True,
            gpu_list=gpu_evidence,
        )

        assert ok is False
        assert err == "GPU 0: unsupported GPU device type"
        mock_gpu.assert_not_called()
        mock_validate.assert_not_called()

    @patch(
        "tas.tas_vm.get_policy",
        return_value=(_POLICY_WITH_GPU, "gpu-test-key"),
    )
    @patch("tas.tas_vm.gpu_validate_claims", return_value=(True, None))
    @patch("tas.tas_vm.gpu_vm_verify", return_value=(True, MagicMock(), None))
    @patch("tas.tas_vm.sev_vm_verify")
    def test_unsupported_type_in_multi_gpu_list_rejects_whole_request(
        self, mock_sev, mock_gpu, mock_validate, _mock_policy
    ):
        """One bad entry fails the request before any GPU is verified."""
        mock_sev.return_value = (True, None)

        gpu_evidence = [
            {
                "type": "gpu-nvidia",
                "evidence": self._make_envelope(b"\x00"),
                "device-index": 0,
            },
            {
                "type": "GPU-NVIDIA",
                "evidence": self._make_envelope(b"\x01"),
                "device-index": 1,
            },
        ]

        ok, _, err = vm_verify(
            MagicMock(),
            MagicMock(),
            self.NONCE,
            "amd-sev-snp",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
            wrapping_key=self.WRAPPING_KEY,
            report_data_binding=True,
            gpu_list=gpu_evidence,
        )

        assert ok is False
        assert err == "GPU 1: unsupported GPU device type"
        mock_gpu.assert_not_called()

    @patch("tas.tas_vm.gpu_validate_claims", return_value=(True, None))
    def test_policy_without_rule_for_verified_device_type_fails(self, mock_validate):
        """A components.gpu section must cover every verified device type."""
        from tas.tas_vm import _apply_gpu_claims_policy

        gpu_results = [
            {
                "device_index": 0,
                "type": "gpu-nvidia",
                "claims": MagicMock(),
                "evidence_hash": b"\x00" * 64,
            }
        ]
        policy_for_other_type = {"gpu-other": _NVIDIA_GPU_POLICY}

        ok, err = _apply_gpu_claims_policy(policy_for_other_type, gpu_results)

        assert ok is False
        assert err == "GPU 0: policy has no rules for device type 'gpu-nvidia'"
        mock_validate.assert_not_called()

    @patch("tas.tas_vm.gpu_validate_claims", return_value=(True, None))
    def test_policy_rule_lookup_is_case_sensitive(self, mock_validate):
        """Policy keys are matched exactly; a case variant is not a match."""
        from tas.tas_vm import _apply_gpu_claims_policy

        gpu_results = [
            {
                "device_index": 0,
                "type": "gpu-nvidia",
                "claims": MagicMock(),
                "evidence_hash": b"\x00" * 64,
            }
        ]

        ok, err = _apply_gpu_claims_policy(
            {"GPU-NVIDIA": _NVIDIA_GPU_POLICY}, gpu_results
        )

        assert ok is False
        assert "no rules for device type" in err
        mock_validate.assert_not_called()

    # -- malformed components / components.gpu fail closed -----------------

    @patch("tas.tas_vm.gpu_validate_claims", return_value=(True, None))
    def test_apply_gpu_claims_policy_none_means_no_policy(self, mock_validate):
        from tas.tas_vm import _apply_gpu_claims_policy

        gpu_results = [
            {
                "device_index": 0,
                "type": "gpu-nvidia",
                "claims": MagicMock(),
                "evidence_hash": b"\x00" * 64,
            }
        ]
        assert _apply_gpu_claims_policy(None, gpu_results) == (True, None)
        mock_validate.assert_not_called()

    @patch("tas.tas_vm.gpu_validate_claims", return_value=(True, None))
    def test_apply_gpu_claims_policy_non_dict_fails_closed(self, mock_validate):
        """A truthy non-dict components.gpu is malformed and must not pass.

        Regression test: a non-dict value previously short-circuited to
        ``(True, None)``, so a malformed policy validated nothing.
        """
        from tas.tas_vm import _apply_gpu_claims_policy

        gpu_results = [
            {
                "device_index": 0,
                "type": "gpu-nvidia",
                "claims": MagicMock(),
                "evidence_hash": b"\x00" * 64,
            }
        ]
        for bad in [[{"gpu-nvidia": _NVIDIA_GPU_POLICY}], "gpu-nvidia", 1, True]:
            ok, err = _apply_gpu_claims_policy(bad, gpu_results)
            assert ok is False, f"{bad!r} accepted"
            assert err == "Policy 'components.gpu' section is malformed"
        mock_validate.assert_not_called()

    def test_extract_gpu_component_policy_shapes(self):
        from tas.tas_vm import _extract_gpu_component_policy

        gpu = {"gpu-nvidia": _NVIDIA_GPU_POLICY}

        # Absent / null sections mean "no GPU rules".
        assert _extract_gpu_component_policy({}) == (None, None)
        assert _extract_gpu_component_policy({"components": None}) == (None, None)
        assert _extract_gpu_component_policy({"components": {}}) == (None, None)
        assert _extract_gpu_component_policy({"components": {"gpu": None}}) == (
            None,
            None,
        )
        # Well-formed.
        assert _extract_gpu_component_policy({"components": {"gpu": gpu}}) == (
            gpu,
            None,
        )
        # Malformed `components`.
        for bad in ["gpu", 1, True, [gpu], [{"gpu": gpu}]]:
            policy, err = _extract_gpu_component_policy({"components": bad})
            assert policy is None
            assert err == "Policy 'components' section is malformed", f"{bad!r}"
        # Malformed `components.gpu` (non-dict or empty).
        for bad in [[gpu], "gpu-nvidia", 1, True, {}]:
            policy, err = _extract_gpu_component_policy({"components": {"gpu": bad}})
            assert policy is None
            assert err == "Policy 'components.gpu' section is malformed", f"{bad!r}"

    @patch("tas.tas_vm.gpu_validate_claims", return_value=(True, None))
    @patch("tas.tas_vm.gpu_vm_verify", return_value=(True, MagicMock(), None))
    @patch("tas.tas_vm.sev_vm_verify")
    def test_vm_verify_fails_closed_on_malformed_components(
        self, mock_sev, mock_gpu, mock_validate
    ):
        """A stored policy with a malformed GPU section fails before any verification."""
        mock_sev.return_value = (True, None)
        gpu_evidence = [
            {
                "type": "gpu-nvidia",
                "evidence": self._make_envelope(b"\xdd"),
                "device-index": 0,
            },
        ]
        gpu = {"gpu-nvidia": _NVIDIA_GPU_POLICY}
        cases = [
            ({"components": "gpu"}, "Policy 'components' section is malformed"),
            (
                {"components": [{"gpu": gpu}]},
                "Policy 'components' section is malformed",
            ),
            (
                {"components": {"gpu": [gpu]}},
                "Policy 'components.gpu' section is malformed",
            ),
            (
                {"components": {"gpu": "gpu-nvidia"}},
                "Policy 'components.gpu' section is malformed",
            ),
            (
                {"components": {"gpu": True}},
                "Policy 'components.gpu' section is malformed",
            ),
            (
                {"components": {"gpu": {}}},
                "Policy 'components.gpu' section is malformed",
            ),
        ]
        for components, expected_error in cases:
            policy = {
                "metadata": {"key_id": "k"},
                "validation_rules": {},
                **components,
            }
            with patch("tas.tas_vm.get_policy", return_value=(policy, "k")):
                # With and without GPU evidence: a malformed policy never passes.
                for gpu_list in (gpu_evidence, None):
                    ok, key_id, err = vm_verify(
                        MagicMock(),
                        MagicMock(),
                        self.NONCE,
                        "amd-sev-snp",
                        self.TEE_EVIDENCE_B64,
                        self.KEY_ID,
                        wrapping_key=self.WRAPPING_KEY,
                        report_data_binding=True,
                        gpu_list=gpu_list,
                    )
                    assert ok is False, f"{components!r} with gpu_list={gpu_list!r}"
                    assert key_id is None
                    assert err == expected_error
        mock_gpu.assert_not_called()
        mock_validate.assert_not_called()
        mock_sev.assert_not_called()

    @patch("tas.tas_vm.gpu_validate_claims", return_value=(True, None))
    @patch("tas.tas_vm.gpu_vm_verify", return_value=(True, MagicMock(), None))
    @patch("tas.tas_vm.sev_vm_verify")
    def test_vm_verify_null_components_means_no_gpu_policy(
        self, mock_sev, mock_gpu, mock_validate
    ):
        """components: null / components.gpu: null are treated as absent."""
        mock_sev.return_value = (True, None)
        for components in ({"components": None}, {"components": {"gpu": None}}):
            policy = {
                "metadata": {"key_id": "k"},
                "validation_rules": {},
                **components,
            }
            with patch("tas.tas_vm.get_policy", return_value=(policy, "k")):
                ok, key_id, err = vm_verify(
                    MagicMock(),
                    MagicMock(),
                    self.NONCE,
                    "amd-sev-snp",
                    self.TEE_EVIDENCE_B64,
                    self.KEY_ID,
                    wrapping_key=self.WRAPPING_KEY,
                    report_data_binding=True,
                    gpu_list=None,
                )
            assert (ok, key_id, err) == (True, "k", None), f"{components!r}"


@pytest.mark.parametrize("tee_type", ["amd-sev-snp", "intel-tdx"])
@pytest.mark.parametrize(
    "binding,wrapping_key",
    [(True, b"key"), (False, b"key"), (True, b""), (True, None)],
)
@pytest.mark.parametrize("failure", [None, "evidence", "claims", "cpu", "missing"])
def test_required_gpu_checks_independent_of_binding(
    tee_type, binding, wrapping_key, failure
):
    """Enforce GPU evidence and policy claims whenever components.gpu is present, regardless of binding."""
    raw_gpu = b"gpu-evidence"
    gpu_list = [
        {
            "type": "gpu-nvidia",
            "device-index": 0,
            "evidence": TestVmVerifyGpuPolicy._make_envelope(raw_gpu),
        }
    ]
    if failure == "missing":
        gpu_list = []
    gpu_result = (
        (False, None, "GPU evidence rejected")
        if failure == "evidence"
        else (True, MagicMock(), None)
    )
    claims_result = (
        (False, "GPU claims rejected") if failure == "claims" else (True, None)
    )
    cpu_result = (False, "CPU policy rejected") if failure == "cpu" else (True, None)
    with (
        patch(
            "tas.tas_vm.get_policy",
            return_value=(_POLICY_WITH_GPU, "gpu-test-key"),
        ),
        patch("tas.tas_vm.gpu_vm_verify", return_value=gpu_result) as gpu,
        patch("tas.tas_vm.gpu_validate_claims", return_value=claims_result) as claims,
        patch("tas.tas_vm.sev_vm_verify", return_value=cpu_result) as sev,
        patch("tas.tas_vm.tdx_vm_verify", return_value=cpu_result) as tdx,
    ):
        ok, key_id, error = vm_verify(
            MagicMock(),
            MagicMock(),
            "nonce",
            tee_type,
            base64.b64encode(b"cpu-evidence").decode(),
            "combined-policy",
            wrapping_key=wrapping_key,
            report_data_binding=binding,
            gpu_list=gpu_list,
        )

    cpu = sev if tee_type == "amd-sev-snp" else tdx
    other_cpu = tdx if tee_type == "amd-sev-snp" else sev
    other_cpu.assert_not_called()
    if failure:
        assert ok is False
        assert key_id is None
        expected_errors = {
            "missing": "Policy requires GPU attestation but no GPU evidence provided",
            "evidence": "GPU evidence rejected",
            "claims": "GPU claims rejected",
            "cpu": "CPU policy rejected",
        }
        assert error == expected_errors[failure]
    else:
        assert (ok, key_id, error) == (True, "gpu-test-key", None)

    if failure == "missing":
        gpu.assert_not_called()
    else:
        gpu.assert_called_once()
        assert gpu.call_args.kwargs["expected_nonce"] == "nonce"
    if failure in ("missing", "evidence"):
        claims.assert_not_called()
    else:
        claims.assert_called_once_with(_NVIDIA_GPU_POLICY, gpu_result[1], 0)
    if failure in ("missing", "evidence", "claims"):
        # GPU failures short-circuit before dispatching to the CPU TEE verifier.
        cpu.assert_not_called()
    else:
        cpu.assert_called_once()
        # Only bound mode with a non-empty wrapping key hashes the key and GPU evidence;
        # unbound or empty-key mode uses the raw nonce bytes for CPU report_data.
        expected = b"nonce"
        if binding and wrapping_key:
            expected = hashlib.sha512(
                expected + wrapping_key + hashlib.sha512(raw_gpu).digest()
            ).digest()
        assert cpu.call_args.kwargs["expected_report_data"] == expected


@pytest.mark.parametrize("binding", [True, False])
@pytest.mark.parametrize("policy_passes", [True, False])
def test_preverified_gpu_results_still_apply_policy(binding, policy_passes):
    """Reuse pre-verified GPU results without re-verifying evidence, while still checking policy claims."""
    claims = MagicMock()
    results = [
        {
            "device_index": 0,
            "type": "gpu-nvidia",
            "claims": claims,
            "evidence_hash": hashlib.sha512(b"gpu-evidence").digest(),
        }
    ]
    with (
        patch("tas.tas_vm._verify_gpu_evidence_list") as gpu_verify,
        patch(
            "tas.tas_vm.gpu_validate_claims",
            return_value=(
                policy_passes,
                None if policy_passes else "GPU claims rejected",
            ),
        ) as validate,
        patch("tas.tas_vm.sev_vm_verify", return_value=(True, None)) as cpu,
    ):
        result = verify(
            MagicMock(),
            "nonce",
            "amd-sev-snp",
            base64.b64encode(b"cpu-evidence").decode(),
            _POLICY_WITH_GPU,
            wrapping_key=b"key",
            report_data_binding=binding,
            gpu_list=[{"type": "gpu-nvidia", "device-index": 0, "evidence": "x"}],
            gpu_results=results,
        )
    gpu_verify.assert_not_called()
    validate.assert_called_once_with(_NVIDIA_GPU_POLICY, claims, 0)
    assert result == (policy_passes, None if policy_passes else "GPU claims rejected")
    assert cpu.call_count == int(policy_passes)


# ── gpu_vm_verify with policy tests ────────────────────────────────


class TestGpuVmVerifyWithPolicy:
    """Tests for gpu_vm_verify when a policy is provided."""

    EVIDENCE_B64 = base64.b64encode(b"\x01\x02\x03").decode()

    @patch("tas.components.gpu_nvidia.nvidia_pytools")
    @patch("tas.components.gpu_nvidia.GPU_PYTOOLS_AVAILABLE", True)
    def test_policy_passed_constructs_attestation_policy(self, mock_nvidia):
        """When gpu_policy is provided, an AttestationPolicy should be created."""
        from tas.components.gpu_nvidia import gpu_vm_verify as direct_verify

        mock_claims = MagicMock()
        mock_claims.hwmodel = "H100"
        mock_nvidia.verify_gpu_evidence.return_value = (True, mock_claims, None)
        mock_nvidia.AttestationPolicy.return_value = MagicMock()

        direct_verify(
            "gpu-nvidia",
            self.EVIDENCE_B64,
            0,
            gpu_policy=_NVIDIA_GPU_POLICY,
        )

        mock_nvidia.AttestationPolicy.assert_called_once_with(
            policy_data=_NVIDIA_GPU_POLICY
        )
        # The constructed policy should be passed to verify_gpu_evidence
        call_kwargs = mock_nvidia.verify_gpu_evidence.call_args
        assert call_kwargs.kwargs["policy"] is not None

    @patch("tas.components.gpu_nvidia.nvidia_pytools")
    @patch("tas.components.gpu_nvidia.GPU_PYTOOLS_AVAILABLE", True)
    def test_no_policy_passes_none(self, mock_nvidia):
        """When gpu_policy is None, policy=None should be passed to verify."""
        from tas.components.gpu_nvidia import gpu_vm_verify as direct_verify

        mock_nvidia.verify_gpu_evidence.return_value = (True, MagicMock(), None)

        direct_verify("gpu-nvidia", self.EVIDENCE_B64, 0, gpu_policy=None)

        call_kwargs = mock_nvidia.verify_gpu_evidence.call_args
        assert call_kwargs.kwargs["policy"] is None

    @patch("tas.components.gpu_nvidia.nvidia_pytools")
    @patch("tas.components.gpu_nvidia.GPU_PYTOOLS_AVAILABLE", True)
    def test_invalid_policy_returns_error(self, mock_nvidia):
        """If the policy is malformed, return an error without calling verify."""
        from tas.components.gpu_nvidia import gpu_vm_verify as direct_verify

        mock_nvidia.AttestationPolicy.side_effect = ValueError(
            "Policy missing required section: authorization-rules"
        )

        ok, key_id, err = direct_verify(
            "gpu-nvidia",
            self.EVIDENCE_B64,
            0,
            gpu_policy={"bad": "policy"},
        )

        assert ok is False
        assert "invalid GPU policy" in err
        mock_nvidia.verify_gpu_evidence.assert_not_called()
