#
# TEE Attestation Service - NVIDIA GPU Attestation via nvidia_pytools
#
# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# TAS component adapter for NVIDIA GPU attestation.
# Delegates verification to the nvidia_pytools library.
#

from tas.tas_logging import get_logger, log_function_entry, log_function_exit

logger = get_logger(__name__)

try:
    import nvidia_pytools

    GPU_PYTOOLS_AVAILABLE = True
except ImportError:
    GPU_PYTOOLS_AVAILABLE = False
    logger.warning(
        "nvidia_pytools not installed - GPU attestation will not be available. "
    )


def gpu_vm_verify(gpu_tee_type, gpu_evidence_b64, device_index, expected_nonce=None):
    """
    Verify a single GPU's attestation evidence via gpu_pytools (NRAS).

    Parameters:
        gpu_tee_type (str): The type of GPU TEE (e.g., "gpu-nvidia").
        gpu_evidence_b64 (str): Base64-encoded GPU attestation evidence envelope.
        device_index (int): The index of the GPU device being verified.
        expected_nonce (str or None): The nonce TAS issued to the agent. If provided,
            the evidence envelope's nonce must match (freshness check).

    Returns:
        is_verified (bool): True if verification is successful, False otherwise.
        key_id (str or None): The key ID (None for GPU verification).
        verify_error (str or None): An error message if verification fails, None otherwise.
    """
    log_function_entry("gpu_vm_verify")

    if not GPU_PYTOOLS_AVAILABLE:
        log_function_exit("gpu_vm_verify", "unavailable")
        return (
            False,
            None,
            (
                f"GPU {device_index}: nvidia_pytools package is not installed. "
                "Install with: pip install nvidia_pytools"
            ),
        )

    ok, claims, error = nvidia_pytools.verify_gpu_evidence(
        gpu_evidence_b64=gpu_evidence_b64,
        device_index=device_index,
        expected_nonce=expected_nonce,
    )

    if ok and claims:
        logger.info(
            f"GPU {device_index} ({gpu_tee_type}, {claims.hwmodel or 'unknown'}): "
            "NRAS remote attestation successful"
        )

    log_function_exit("gpu_vm_verify", "verified" if ok else "failed")
    return ok, None, error
