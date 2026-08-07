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


def gpu_vm_verify(
    gpu_tee_type,
    gpu_evidence_b64,
    device_index,
    expected_nonce=None,
    gpu_policy=None,
    mode="remote",
    collateral=None,
):
    """
    Verify a single GPU's attestation evidence via nvidia_pytools.

    Parameters:
        gpu_tee_type (str): The type of GPU TEE (e.g., "gpu-nvidia").
        gpu_evidence_b64 (str): Base64-encoded GPU attestation evidence envelope.
        device_index (int): The index of the GPU device being verified.
        expected_nonce (str or None): The nonce TAS issued to the agent. If provided,
            the evidence envelope's nonce must match (freshness check).
        gpu_policy (dict or None): NVIDIA GPU policy dict (with "authorization-rules")
            to validate claims against. If None, no policy validation is performed.
        mode (str): Verification mode — "remote" (NRAS) or "local".
        collateral (nvidia_pytools.GpuCollateral or None): Pre-fetched collateral
            for local mode. RIMs present are used directly; any missing are fetched
            by the verifier and stored back into this object so the caller can
            persist them. Ignored in remote mode.

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

    # Construct AttestationPolicy if policy rules provided
    policy = None
    if gpu_policy:
        try:
            policy = nvidia_pytools.AttestationPolicy(policy_data=gpu_policy)
        except (ValueError, Exception) as e:
            log_function_exit("gpu_vm_verify", "policy_error")
            return (
                False,
                None,
                f"GPU {device_index}: invalid GPU policy: {e}",
            )

    ok, claims, error = nvidia_pytools.verify_gpu_evidence(
        gpu_evidence_b64=gpu_evidence_b64,
        device_index=device_index,
        expected_nonce=expected_nonce,
        policy=policy,
        mode=mode,
        collateral=collateral,
    )

    if ok and claims:
        logger.info(
            f"GPU {device_index} ({gpu_tee_type}, {claims.hwmodel or 'unknown'}): "
            f"{mode} attestation successful"
        )

    log_function_exit("gpu_vm_verify", "verified" if ok else "failed")
    return ok, None, error


def gpu_get_collateral_refs(gpu_evidence_b64, device_index=0):
    """
    Parse GPU evidence far enough to determine which collateral (RIMs) is needed.

    Used by the caller to look up cached collateral before local verification.

    Returns:
        nvidia_pytools.GpuCollateralRefs, or None if GPU tooling is unavailable
        or the evidence cannot be parsed.
    """
    if not GPU_PYTOOLS_AVAILABLE:
        return None
    return nvidia_pytools.get_collateral_refs(gpu_evidence_b64, device_index)


def gpu_new_collateral(rims=None):
    """
    Build a GpuCollateral from a mapping of rim_id -> raw RIM XML bytes.

    Returns:
        nvidia_pytools.GpuCollateral, or None if GPU tooling is unavailable.
    """
    if not GPU_PYTOOLS_AVAILABLE:
        return None
    return nvidia_pytools.GpuCollateral(rims=dict(rims or {}))
