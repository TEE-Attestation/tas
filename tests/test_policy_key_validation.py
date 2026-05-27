#
# TEE Attestation Service - Tests for policy key validation
#
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This module provides unit tests for the policy key validation logic,
# including the validate_policy_key() helper and POLICY_KEY_COMPONENT_RE regex.
#

import pytest

from tas.policy_helper import POLICY_KEY_COMPONENT_RE, validate_policy_key


class TestValidatePolicyKey:
    """Test cases for the validate_policy_key function.

    Policy keys now use the format: policy:{policy_id}
    where policy_id contains only alphanumeric characters, hyphens, underscores, and dots.
    """

    # --- Valid keys ---

    def test_valid_simple_policy_id(self):
        """Standard policy key with simple ID."""
        is_valid, error = validate_policy_key("policy:my-sev-policy-001")
        assert is_valid is True
        assert error is None

    def test_valid_policy_id_with_dots(self):
        """Policy ID containing dots."""
        is_valid, error = validate_policy_key("policy:policy.with.dots")
        assert is_valid is True
        assert error is None

    def test_valid_policy_id_with_underscores(self):
        """Policy ID containing underscores."""
        is_valid, error = validate_policy_key("policy:policy_with_underscores")
        assert is_valid is True
        assert error is None

    def test_valid_policy_id_minimal(self):
        """Minimal single-character policy_id."""
        is_valid, error = validate_policy_key("policy:a")
        assert is_valid is True
        assert error is None

    def test_valid_policy_id_numeric(self):
        """Purely numeric policy_id."""
        is_valid, error = validate_policy_key("policy:12345")
        assert is_valid is True
        assert error is None

    def test_valid_policy_id_mixed(self):
        """Mixed alphanumeric with hyphens."""
        is_valid, error = validate_policy_key("policy:sev-prod-v2.1_final")
        assert is_valid is True
        assert error is None

    # --- Invalid keys: old format (policy:{type}:{key_id}) must be rejected ---

    def test_old_format_three_parts_rejected(self):
        """Old-style policy:TYPE:key_id format must be rejected."""
        is_valid, error = validate_policy_key("policy:SEV:my-key-1")
        assert is_valid is False

    def test_old_format_tdx_rejected(self):
        """Old-style policy:TDX:key_id format must be rejected."""
        is_valid, error = validate_policy_key("policy:TDX:my-key-1")
        assert is_valid is False

    def test_old_format_extra_colons_rejected(self):
        """Multiple colons in the key must be rejected."""
        is_valid, error = validate_policy_key("policy:SEV:my:key:extra")
        assert is_valid is False

    # --- Invalid keys: wrong structure ---

    def test_invalid_empty_policy_id(self):
        """Empty policy_id after colon."""
        is_valid, error = validate_policy_key("policy:")
        assert is_valid is False

    def test_invalid_wrong_prefix(self):
        """Wrong prefix (not 'policy')."""
        is_valid, error = validate_policy_key("nonce:abc")
        assert is_valid is False

    def test_invalid_no_prefix(self):
        """No 'policy' prefix at all."""
        is_valid, error = validate_policy_key("my-policy-id")
        assert is_valid is False

    def test_invalid_empty_string(self):
        """Empty string."""
        is_valid, error = validate_policy_key("")
        assert is_valid is False

    def test_invalid_just_prefix(self):
        """Just the word 'policy' with no segments."""
        is_valid, error = validate_policy_key("policy")
        assert is_valid is False

    def test_invalid_none(self):
        """None input."""
        is_valid, error = validate_policy_key(None)
        assert is_valid is False

    def test_invalid_non_string(self):
        """Non-string input."""
        is_valid, error = validate_policy_key(12345)
        assert is_valid is False

    # --- Invalid keys: dangerous characters ---

    def test_invalid_glob_asterisk(self):
        """Redis glob character * in policy_id."""
        is_valid, error = validate_policy_key("policy:my-policy*")
        assert is_valid is False

    def test_invalid_glob_question(self):
        """Redis glob character ? in policy_id."""
        is_valid, error = validate_policy_key("policy:my-policy?")
        assert is_valid is False

    def test_invalid_glob_brackets(self):
        """Redis glob characters [] in policy_id."""
        is_valid, error = validate_policy_key("policy:my-policy[1]")
        assert is_valid is False

    def test_invalid_newline(self):
        """Newline character in policy_id."""
        is_valid, error = validate_policy_key("policy:my-policy\n")
        assert is_valid is False

    def test_invalid_space(self):
        """Space character in policy_id."""
        is_valid, error = validate_policy_key("policy:my policy")
        assert is_valid is False

    def test_invalid_null_byte(self):
        """Null byte in policy_id."""
        is_valid, error = validate_policy_key("policy:policy\x00")
        assert is_valid is False

    def test_invalid_backslash(self):
        """Backslash in policy_id."""
        is_valid, error = validate_policy_key("policy:my\\policy")
        assert is_valid is False

    def test_invalid_semicolon(self):
        """Semicolon in policy_id."""
        is_valid, error = validate_policy_key("policy:my;policy")
        assert is_valid is False


class TestPolicyKeyComponentRegex:
    """Test cases for the POLICY_KEY_COMPONENT_RE regex used in store validation."""

    # --- Valid components ---

    def test_valid_simple(self):
        assert POLICY_KEY_COMPONENT_RE.match("SEV")

    def test_valid_lowercase(self):
        assert POLICY_KEY_COMPONENT_RE.match("sev")

    def test_valid_with_hyphens(self):
        assert POLICY_KEY_COMPONENT_RE.match("my-key-1")

    def test_valid_with_underscores(self):
        assert POLICY_KEY_COMPONENT_RE.match("my_key_1")

    def test_valid_with_dots(self):
        assert POLICY_KEY_COMPONENT_RE.match("key.with.dots")

    def test_valid_numeric(self):
        assert POLICY_KEY_COMPONENT_RE.match("12345")

    def test_valid_single_char(self):
        assert POLICY_KEY_COMPONENT_RE.match("a")

    # --- Invalid components ---

    def test_invalid_empty(self):
        assert POLICY_KEY_COMPONENT_RE.match("") is None

    def test_invalid_asterisk(self):
        assert POLICY_KEY_COMPONENT_RE.match("key*") is None

    def test_invalid_question_mark(self):
        assert POLICY_KEY_COMPONENT_RE.match("key?") is None

    def test_invalid_brackets(self):
        assert POLICY_KEY_COMPONENT_RE.match("key[1]") is None

    def test_invalid_space(self):
        assert POLICY_KEY_COMPONENT_RE.match("my key") is None

    def test_invalid_newline(self):
        assert POLICY_KEY_COMPONENT_RE.match("key\n") is None

    def test_invalid_colon(self):
        assert POLICY_KEY_COMPONENT_RE.match("key:value") is None

    def test_invalid_backslash(self):
        assert POLICY_KEY_COMPONENT_RE.match("key\\value") is None

    def test_invalid_semicolon(self):
        assert POLICY_KEY_COMPONENT_RE.match("key;value") is None

    def test_invalid_null_byte(self):
        assert POLICY_KEY_COMPONENT_RE.match("key\x00") is None
