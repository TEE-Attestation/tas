#
# TEE Attestation Service - Component Verification Modules
#
# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#

# Component types a policy's ``components`` section may contain, and the GPU
# device types TAS knows how to verify. ``components.gpu`` is keyed by the GPU
# device types, and each GPU evidence entry's ``type`` must be one of them.
# Defined here (rather than in tas_vm) so both the verifier and the policy
# upload validator can import them without a circular dependency.
SUPPORTED_COMPONENT_TYPES = frozenset({"gpu"})
SUPPORTED_GPU_TYPES = frozenset({"gpu-nvidia"})
