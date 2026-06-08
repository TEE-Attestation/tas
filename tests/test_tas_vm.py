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

from tas.tas_vm import gpu_vm_verify, vm_verify

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
        """Successful nvidia_pytools verification returns (True, None, None)."""
        from tas.components.gpu_nvidia import gpu_vm_verify as direct_verify

        mock_claims = MagicMock()
        mock_claims.hwmodel = "H100"
        mock_nvidia.verify_gpu_evidence.return_value = (True, mock_claims, None)

        ok, key_id, err = direct_verify("gpu-nvidia", self.EVIDENCE_B64, 0)
        assert ok is True
        assert key_id is None
        assert err is None
        mock_nvidia.verify_gpu_evidence.assert_called_once_with(
            gpu_evidence_b64=self.EVIDENCE_B64,
            device_index=0,
            expected_nonce=None,
            policy=None,
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
            MagicMock(), "", "amd-sev-snp", self.VALID_EVIDENCE_B64, "k1"
        )
        assert ok is False
        assert "Nonce" in err

    def test_none_nonce_rejected(self):
        ok, _, err = vm_verify(
            MagicMock(), None, "amd-sev-snp", self.VALID_EVIDENCE_B64, "k1"
        )
        assert ok is False
        assert "Nonce" in err

    def test_invalid_tee_type_rejected(self):
        ok, _, err = vm_verify(
            MagicMock(), "abc123", "bad-type", self.VALID_EVIDENCE_B64, "k1"
        )
        assert ok is False
        assert "TEE type" in err

    def test_invalid_base64_evidence_rejected(self):
        ok, _, err = vm_verify(MagicMock(), "abc123", "amd-sev-snp", "!!!bad!!!", "k1")
        assert ok is False
        assert "invalid" in err.lower()

    def test_empty_evidence_rejected(self):
        empty_b64 = base64.b64encode(b"").decode()
        ok, _, err = vm_verify(MagicMock(), "abc123", "amd-sev-snp", empty_b64, "k1")
        assert ok is False
        assert "empty" in err.lower()


# ── vm_verify report_data_binding tests ─────────────────────────────


@patch(
    "tas.tas_vm.get_policy_from_redis",
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
    "tas.tas_vm.get_policy_from_redis",
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
            MagicMock(), self.NONCE, "amd-sev-snp", self.TEE_EVIDENCE_B64, self.KEY_ID
        )
        assert ok is True
        assert key_id == "prop-key"
        assert err is None

    @patch("tas.tas_vm.sev_vm_verify")
    def test_sev_failure_propagated(self, mock_sev, _mock_policy):
        """vm_verify should return (False, None, error) when sev_vm_verify fails."""
        mock_sev.return_value = (False, "SEV verification failed")
        ok, key_id, err = vm_verify(
            MagicMock(), self.NONCE, "amd-sev-snp", self.TEE_EVIDENCE_B64, self.KEY_ID
        )
        assert ok is False
        assert key_id is None
        assert err == "SEV verification failed"

    @patch("tas.tas_vm.tdx_vm_verify")
    def test_tdx_success_propagated(self, mock_tdx, _mock_policy):
        """vm_verify should return (True, key_id, None) when tdx_vm_verify succeeds."""
        mock_tdx.return_value = (True, None)
        ok, key_id, err = vm_verify(
            MagicMock(), self.NONCE, "intel-tdx", self.TEE_EVIDENCE_B64, self.KEY_ID
        )
        assert ok is True
        assert key_id == "prop-key"
        assert err is None

    @patch("tas.tas_vm.tdx_vm_verify")
    def test_tdx_failure_propagated(self, mock_tdx, _mock_policy):
        """vm_verify should return (False, None, error) when tdx_vm_verify fails."""
        mock_tdx.return_value = (False, "TDX verification failed")
        ok, key_id, err = vm_verify(
            MagicMock(), self.NONCE, "intel-tdx", self.TEE_EVIDENCE_B64, self.KEY_ID
        )
        assert ok is False
        assert key_id is None
        assert err == "TDX verification failed"


# ── vm_verify GPU evidence tests ────────────────────────────────────


@patch(
    "tas.tas_vm.get_policy_from_redis",
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
                "type": "nvidia-hopper",
                "evidence": self.GPU_EVIDENCE_B64,
                "device-index": i,
            }
            for i in range(17)
        ]
        ok, _, err = vm_verify(
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
                "type": "nvidia-hopper",
                "evidence": self.GPU_EVIDENCE_B64,
                "device-index": i,
            }
            for i in range(16)
        ]
        ok, _, err = vm_verify(
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
                "type": "nvidia-hopper",
                "evidence": self.GPU_EVIDENCE_B64,
                "device-index": 0,
            },
        ]
        ok, _, err = vm_verify(
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
                "type": "nvidia-hopper",
                "evidence": self._make_envelope(gpu1_raw),
                "device-index": 1,
            },
            {
                "type": "nvidia-hopper",
                "evidence": self._make_envelope(gpu0_raw),
                "device-index": 0,
            },
        ]

        vm_verify(
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
                "type": "t",
                "evidence": self._make_envelope(b"gpu2"),
                "device-index": 2,
            },
            {
                "type": "t",
                "evidence": self._make_envelope(b"gpu0"),
                "device-index": 0,
            },
            {
                "type": "t",
                "evidence": self._make_envelope(b"gpu1"),
                "device-index": 1,
            },
        ]

        vm_verify(
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
                "type": "nvidia-hopper",
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
                "type": "t",
                "evidence": self._make_envelope(b"g0"),
                "device-index": 0,
            },
            {
                "type": "t",
                "evidence": self._make_envelope(b"g1"),
                "device-index": 1,
            },
        ]

        ok, _, err = vm_verify(
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
        "tas.tas_vm.get_policy_from_redis",
        return_value=(_POLICY_WITH_GPU, "gpu-test-key"),
    )
    def test_gpu_required_by_policy_but_no_evidence_fails(self, _mock_policy):
        """If policy has components.gpu but no GPU evidence provided, fail."""
        ok, _, err = vm_verify(
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
        "tas.tas_vm.get_policy_from_redis",
        return_value=(_POLICY_NO_COMPONENTS, "no-gpu-key"),
    )
    @patch("tas.tas_vm.sev_vm_verify")
    def test_gpu_evidence_without_policy_warns_but_passes(self, mock_sev, _mock_policy):
        """GPU evidence without components.gpu in policy logs warning, still verifies."""
        mock_sev.return_value = (True, None)
        gpu_evidence = [
            {
                "type": "nvidia-hopper",
                "evidence": self._make_envelope(b"\xaa"),
                "device-index": 0,
            },
        ]

        # GPU verify will be called without policy (None), should still work
        with patch("tas.tas_vm.gpu_vm_verify", return_value=(True, None, None)):
            ok, key_id, err = vm_verify(
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
        "tas.tas_vm.get_policy_from_redis",
        return_value=(_POLICY_WITH_GPU, "gpu-test-key"),
    )
    @patch("tas.tas_vm.gpu_vm_verify")
    @patch("tas.tas_vm.sev_vm_verify")
    def test_nvidia_policy_passed_to_gpu_vm_verify(
        self, mock_sev, mock_gpu, _mock_policy
    ):
        """The NVIDIA policy should be passed to gpu_vm_verify for gpu-nvidia GPUs."""
        mock_sev.return_value = (True, None)
        mock_gpu.return_value = (True, None, None)

        gpu_evidence = [
            {
                "type": "gpu-nvidia",
                "evidence": self._make_envelope(b"\xbb"),
                "device-index": 0,
            },
        ]

        vm_verify(
            MagicMock(),
            self.NONCE,
            "amd-sev-snp",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
            wrapping_key=self.WRAPPING_KEY,
            report_data_binding=True,
            gpu_list=gpu_evidence,
        )

        # gpu_vm_verify should be called with the nvidia policy
        call_kwargs = mock_gpu.call_args
        assert call_kwargs.kwargs["gpu_policy"] == _NVIDIA_GPU_POLICY

    @patch(
        "tas.tas_vm.get_policy_from_redis",
        return_value=(_POLICY_WITH_GPU, "gpu-test-key"),
    )
    @patch("tas.tas_vm.gpu_vm_verify")
    @patch("tas.tas_vm.sev_vm_verify")
    def test_non_matching_device_type_gets_no_policy(
        self, mock_sev, mock_gpu, _mock_policy
    ):
        """GPUs whose device type has no matching policy key get gpu_policy=None."""
        mock_sev.return_value = (True, None)
        mock_gpu.return_value = (True, None, None)

        gpu_evidence = [
            {
                "type": "amd-gpu",
                "evidence": self._make_envelope(b"\xcc"),
                "device-index": 0,
            },
        ]

        vm_verify(
            MagicMock(),
            self.NONCE,
            "amd-sev-snp",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
            wrapping_key=self.WRAPPING_KEY,
            report_data_binding=True,
            gpu_list=gpu_evidence,
        )

        call_kwargs = mock_gpu.call_args
        assert call_kwargs.kwargs["gpu_policy"] is None


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
