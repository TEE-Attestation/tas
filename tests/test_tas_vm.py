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
from unittest.mock import MagicMock, patch

from tas.tas_vm import gpu_vm_verify, vm_verify

# ── gpu_vm_verify tests ─────────────────────────────────────────────


class TestGpuVmVerify:
    """Tests for the gpu_vm_verify stub function."""

    def test_empty_evidence_returns_error(self):
        """Empty base64 payload should be rejected."""
        empty_b64 = base64.b64encode(b"").decode()
        ok, err = gpu_vm_verify("nvidia-hopper", empty_b64, 0)
        assert ok is False
        assert "empty evidence" in err

    def test_valid_evidence_returns_not_implemented(self):
        """Non-empty evidence should return a 'not implemented' error (stub)."""
        evidence_b64 = base64.b64encode(b"\x01\x02\x03").decode()
        ok, err = gpu_vm_verify("nvidia-hopper", evidence_b64, 0)
        assert ok is False
        assert "not yet implemented" in err

    def test_invalid_base64_returns_error(self):
        """Invalid base64 should be caught and return an error."""
        ok, err = gpu_vm_verify("nvidia-hopper", "!!!not-base64!!!", 0)
        assert ok is False
        assert "verification error" in err

    def test_device_index_in_error_message(self):
        """Device index should appear in the error message."""
        evidence_b64 = base64.b64encode(b"\xaa").decode()
        ok, err = gpu_vm_verify("nvidia-hopper", evidence_b64, 42)
        assert ok is False
        assert "42" in err

    def test_tee_type_in_error_message(self):
        """GPU TEE type should appear in the error message."""
        evidence_b64 = base64.b64encode(b"\xaa").decode()
        ok, err = gpu_vm_verify("nvidia-hopper", evidence_b64, 0)
        assert ok is False
        assert "nvidia-hopper" in err


# ── vm_verify input validation tests ────────────────────────────────


class TestVmVerifyInputValidation:
    """Tests for vm_verify input validation (before TEE dispatch)."""

    VALID_EVIDENCE_B64 = base64.b64encode(b"\x01\x02\x03").decode()

    def test_empty_nonce_rejected(self):
        ok, err = vm_verify(
            MagicMock(), "", "amd-sev-snp", self.VALID_EVIDENCE_B64, "k1"
        )
        assert ok is False
        assert "Nonce" in err

    def test_none_nonce_rejected(self):
        ok, err = vm_verify(
            MagicMock(), None, "amd-sev-snp", self.VALID_EVIDENCE_B64, "k1"
        )
        assert ok is False
        assert "Nonce" in err

    def test_invalid_tee_type_rejected(self):
        ok, err = vm_verify(
            MagicMock(), "abc123", "bad-type", self.VALID_EVIDENCE_B64, "k1"
        )
        assert ok is False
        assert "TEE type" in err

    def test_invalid_base64_evidence_rejected(self):
        ok, err = vm_verify(MagicMock(), "abc123", "amd-sev-snp", "!!!bad!!!", "k1")
        assert ok is False
        assert "invalid" in err.lower()

    def test_empty_evidence_rejected(self):
        empty_b64 = base64.b64encode(b"").decode()
        ok, err = vm_verify(MagicMock(), "abc123", "amd-sev-snp", empty_b64, "k1")
        assert ok is False
        assert "empty" in err.lower()


# ── vm_verify report_data_binding tests ─────────────────────────────


class TestVmVerifyReportDataBinding:
    """Tests for the report_data_binding computation in vm_verify."""

    NONCE = "test-nonce-1234"
    TEE_EVIDENCE_B64 = base64.b64encode(b"\xde\xad\xbe\xef").decode()
    WRAPPING_KEY = b"\x00" * 32
    KEY_ID = "test-key"

    @patch("tas.tas_vm.sev_vm_verify")
    def test_binding_computes_sha512(self, mock_sev):
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
    def test_no_binding_uses_nonce(self, mock_sev):
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
    def test_binding_false_uses_nonce(self, mock_sev):
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
    def test_binding_true_no_wrapping_key_uses_nonce(self, mock_sev):
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
    def test_binding_dispatches_to_tdx(self, mock_tdx):
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


class TestVmVerifyReturnPropagation:
    """Tests that vm_verify correctly returns the result from TEE verifiers."""

    NONCE = "prop-nonce"
    TEE_EVIDENCE_B64 = base64.b64encode(b"\xab\xcd").decode()
    KEY_ID = "prop-key"

    @patch("tas.tas_vm.sev_vm_verify")
    def test_sev_success_propagated(self, mock_sev):
        """vm_verify should return (True, None) when sev_vm_verify succeeds."""
        mock_sev.return_value = (True, None)
        ok, err = vm_verify(
            MagicMock(), self.NONCE, "amd-sev-snp", self.TEE_EVIDENCE_B64, self.KEY_ID
        )
        assert ok is True
        assert err is None

    @patch("tas.tas_vm.sev_vm_verify")
    def test_sev_failure_propagated(self, mock_sev):
        """vm_verify should return (False, error) when sev_vm_verify fails."""
        mock_sev.return_value = (False, "SEV verification failed")
        ok, err = vm_verify(
            MagicMock(), self.NONCE, "amd-sev-snp", self.TEE_EVIDENCE_B64, self.KEY_ID
        )
        assert ok is False
        assert err == "SEV verification failed"

    @patch("tas.tas_vm.tdx_vm_verify")
    def test_tdx_success_propagated(self, mock_tdx):
        """vm_verify should return (True, None) when tdx_vm_verify succeeds."""
        mock_tdx.return_value = (True, None)
        ok, err = vm_verify(
            MagicMock(), self.NONCE, "intel-tdx", self.TEE_EVIDENCE_B64, self.KEY_ID
        )
        assert ok is True
        assert err is None

    @patch("tas.tas_vm.tdx_vm_verify")
    def test_tdx_failure_propagated(self, mock_tdx):
        """vm_verify should return (False, error) when tdx_vm_verify fails."""
        mock_tdx.return_value = (False, "TDX verification failed")
        ok, err = vm_verify(
            MagicMock(), self.NONCE, "intel-tdx", self.TEE_EVIDENCE_B64, self.KEY_ID
        )
        assert ok is False
        assert err == "TDX verification failed"


# ── vm_verify GPU evidence tests ────────────────────────────────────


class TestVmVerifyGpuEvidence:
    """Tests for GPU evidence handling in vm_verify."""

    NONCE = "gpu-test-nonce"
    TEE_EVIDENCE_B64 = base64.b64encode(b"\xca\xfe").decode()
    WRAPPING_KEY = b"\x11" * 16
    KEY_ID = "gpu-key"
    GPU_EVIDENCE_RAW = b"\xaa\xbb\xcc"
    GPU_EVIDENCE_B64 = base64.b64encode(GPU_EVIDENCE_RAW).decode()

    def test_gpu_evidence_too_many_rejected(self):
        """More than 16 GPU entries should be rejected."""
        gpu_evidence = [
            {
                "tee-type": "nvidia-hopper",
                "tee-evidence": self.GPU_EVIDENCE_B64,
                "device-index": i,
            }
            for i in range(17)
        ]
        ok, err = vm_verify(
            MagicMock(),
            self.NONCE,
            "amd-sev-snp",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
            wrapping_key=self.WRAPPING_KEY,
            report_data_binding=True,
            gpu_evidence=gpu_evidence,
        )
        assert ok is False
        assert "max 16" in err

    def test_gpu_evidence_exactly_16_passes_cap(self):
        """Exactly 16 GPU entries should not be rejected by the cap."""
        gpu_evidence = [
            {
                "tee-type": "nvidia-hopper",
                "tee-evidence": self.GPU_EVIDENCE_B64,
                "device-index": i,
            }
            for i in range(16)
        ]
        ok, err = vm_verify(
            MagicMock(),
            self.NONCE,
            "amd-sev-snp",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
            wrapping_key=self.WRAPPING_KEY,
            report_data_binding=True,
            gpu_evidence=gpu_evidence,
        )
        assert ok is False
        # Error should be from gpu_vm_verify stub, not the cap
        assert "max 16" not in err

    def test_gpu_failure_stops_verification(self):
        """If a GPU fails verification, vm_verify should return its error."""
        gpu_evidence = [
            {
                "tee-type": "nvidia-hopper",
                "tee-evidence": self.GPU_EVIDENCE_B64,
                "device-index": 0,
            },
        ]
        ok, err = vm_verify(
            MagicMock(),
            self.NONCE,
            "amd-sev-snp",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
            wrapping_key=self.WRAPPING_KEY,
            report_data_binding=True,
            gpu_evidence=gpu_evidence,
        )
        assert ok is False
        assert "not yet implemented" in err

    @patch("tas.tas_vm.gpu_vm_verify", return_value=(True, None))
    @patch("tas.tas_vm.sev_vm_verify")
    def test_gpu_hashes_included_in_binding(self, mock_sev, mock_gpu):
        """GPU evidence SHA-512 hashes should be included in the binding."""
        mock_sev.return_value = (True, None)

        gpu0_raw = b"\xaa\xbb"
        gpu1_raw = b"\xcc\xdd"
        gpu_evidence = [
            {
                "tee-type": "nvidia-hopper",
                "tee-evidence": base64.b64encode(gpu1_raw).decode(),
                "device-index": 1,
            },
            {
                "tee-type": "nvidia-hopper",
                "tee-evidence": base64.b64encode(gpu0_raw).decode(),
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
            gpu_evidence=gpu_evidence,
        )

        # Build expected hash: sorted by device-index (0 first, then 1)
        hash_input = self.NONCE.encode("utf-8") + self.WRAPPING_KEY
        hash_input += hashlib.sha512(gpu0_raw).digest()
        hash_input += hashlib.sha512(gpu1_raw).digest()
        expected = hashlib.sha512(hash_input).digest()

        call_kwargs = mock_sev.call_args
        assert call_kwargs.kwargs["expected_report_data"] == expected

    @patch("tas.tas_vm.gpu_vm_verify", return_value=(True, None))
    @patch("tas.tas_vm.sev_vm_verify")
    def test_gpu_evidence_sorted_by_device_index(self, mock_sev, mock_gpu):
        """GPU evidence should be sorted by device-index for deterministic hashing."""
        mock_sev.return_value = (True, None)

        gpu_entries = [
            {
                "tee-type": "t",
                "tee-evidence": base64.b64encode(b"gpu2").decode(),
                "device-index": 2,
            },
            {
                "tee-type": "t",
                "tee-evidence": base64.b64encode(b"gpu0").decode(),
                "device-index": 0,
            },
            {
                "tee-type": "t",
                "tee-evidence": base64.b64encode(b"gpu1").decode(),
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
            gpu_evidence=gpu_entries,
        )

        # gpu_vm_verify should have been called in sorted order: 0, 1, 2
        calls = mock_gpu.call_args_list
        device_indices = [c.args[2] for c in calls]
        assert device_indices == [0, 1, 2]

    def test_gpu_evidence_without_binding_ignored(self):
        """GPU evidence without report_data_binding should not trigger GPU verify."""
        gpu_evidence = [
            {
                "tee-type": "nvidia-hopper",
                "tee-evidence": self.GPU_EVIDENCE_B64,
                "device-index": 0,
            },
        ]
        with patch("tas.tas_vm.sev_vm_verify") as mock_sev, patch(
            "tas.tas_vm.gpu_vm_verify"
        ) as mock_gpu:
            mock_sev.return_value = (True, None)

            vm_verify(
                MagicMock(),
                self.NONCE,
                "amd-sev-snp",
                self.TEE_EVIDENCE_B64,
                self.KEY_ID,
                wrapping_key=self.WRAPPING_KEY,
                report_data_binding=False,
                gpu_evidence=gpu_evidence,
            )

            mock_gpu.assert_not_called()

    @patch("tas.tas_vm.gpu_vm_verify", return_value=(True, None))
    @patch("tas.tas_vm.sev_vm_verify")
    def test_binding_without_gpu_evidence_no_gpu_verify(self, mock_sev, mock_gpu):
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
            gpu_evidence=None,
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
    def test_second_gpu_failure_after_first_passes(self, mock_sev, mock_gpu):
        """If the second GPU fails, its error should be returned."""
        mock_gpu.side_effect = [
            (True, None),  # GPU 0 passes
            (False, "GPU 1 attestation invalid"),  # GPU 1 fails
        ]

        gpu_evidence = [
            {
                "tee-type": "t",
                "tee-evidence": base64.b64encode(b"g0").decode(),
                "device-index": 0,
            },
            {
                "tee-type": "t",
                "tee-evidence": base64.b64encode(b"g1").decode(),
                "device-index": 1,
            },
        ]

        ok, err = vm_verify(
            MagicMock(),
            self.NONCE,
            "amd-sev-snp",
            self.TEE_EVIDENCE_B64,
            self.KEY_ID,
            wrapping_key=self.WRAPPING_KEY,
            report_data_binding=True,
            gpu_evidence=gpu_evidence,
        )

        assert ok is False
        assert "GPU 1" in err
