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
    """Test cases for the validate_policy_key function."""

    # --- Valid keys ---

    def test_valid_sev_key(self):
        """Standard SEV policy key."""
        is_valid, error = validate_policy_key("policy:SEV:my-key-1")
        assert is_valid is True
        assert error is None

    def test_valid_tdx_key(self):
        """Standard TDX policy key."""
        is_valid, error = validate_policy_key("policy:TDX:my-key-1")
        assert is_valid is True
        assert error is None

    def test_valid_key_with_dots(self):
        """Key ID containing dots."""
        is_valid, error = validate_policy_key("policy:SEV:key.with.dots")
        assert is_valid is True
        assert error is None

    def test_valid_key_with_underscores(self):
        """Key ID containing underscores."""
        is_valid, error = validate_policy_key("policy:SEV:key_with_underscores")
        assert is_valid is True
        assert error is None

    def test_valid_key_minimal_key_id(self):
        """Minimal single-character key_id."""
        is_valid, error = validate_policy_key("policy:SEV:a")
        assert is_valid is True
        assert error is None

    def test_valid_key_minimal_type(self):
        """Minimal single-character type."""
        is_valid, error = validate_policy_key("policy:X:my-key")
        assert is_valid is True
        assert error is None

    def test_valid_key_custom_type(self):
        """Custom type with hyphens."""
        is_valid, error = validate_policy_key("policy:MY-TYPE:a")
        assert is_valid is True
        assert error is None

    def test_valid_key_numeric_components(self):
        """Purely numeric type and key_id."""
        is_valid, error = validate_policy_key("policy:123:456")
        assert is_valid is True
        assert error is None

    # --- Invalid keys: wrong structure ---

    def test_invalid_missing_key_id(self):
        """Missing key_id segment (only two parts)."""
        is_valid, error = validate_policy_key("policy:SEV")
        assert is_valid is False

    def test_invalid_empty_key_id(self):
        """Empty key_id after trailing colon."""
        is_valid, error = validate_policy_key("policy:SEV:")
        assert is_valid is False

    def test_invalid_empty_type(self):
        """Empty type segment."""
        is_valid, error = validate_policy_key("policy::key-1")
        assert is_valid is False

    def test_invalid_empty_prefix(self):
        """Empty first segment."""
        is_valid, error = validate_policy_key(":SEV:key-1")
        assert is_valid is False

    def test_invalid_wrong_prefix(self):
        """Wrong prefix (not 'policy')."""
        is_valid, error = validate_policy_key("nonce:abc:def")
        assert is_valid is False

    def test_invalid_no_prefix(self):
        """No 'policy' prefix at all."""
        is_valid, error = validate_policy_key("SEV:key-1")
        assert is_valid is False

    def test_invalid_extra_colons(self):
        """Too many colon-separated segments."""
        is_valid, error = validate_policy_key("policy:SEV:my:key:extra")
        assert is_valid is False

    def test_invalid_trailing_colon(self):
        """Trailing colon after key_id."""
        is_valid, error = validate_policy_key("policy:SEV:my-key-1:")
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

    def test_invalid_glob_asterisk_in_key_id(self):
        """Redis glob character * in key_id."""
        is_valid, error = validate_policy_key("policy:SEV:my-key*")
        assert is_valid is False

    def test_invalid_glob_question_in_key_id(self):
        """Redis glob character ? in key_id."""
        is_valid, error = validate_policy_key("policy:SEV:my-key?")
        assert is_valid is False

    def test_invalid_glob_brackets_in_key_id(self):
        """Redis glob characters [] in key_id."""
        is_valid, error = validate_policy_key("policy:SEV:my-key[1]")
        assert is_valid is False

    def test_invalid_glob_asterisk_in_type(self):
        """Redis glob character * in type segment."""
        is_valid, error = validate_policy_key("policy:S*V:key-1")
        assert is_valid is False

    def test_invalid_newline_in_key_id(self):
        """Newline character in key_id."""
        is_valid, error = validate_policy_key("policy:SEV:my-key\n")
        assert is_valid is False

    def test_invalid_space_in_key_id(self):
        """Space character in key_id."""
        is_valid, error = validate_policy_key("policy:SEV:my key")
        assert is_valid is False

    def test_invalid_space_in_type(self):
        """Space character in type segment."""
        is_valid, error = validate_policy_key("policy:S V:key-1")
        assert is_valid is False

    def test_invalid_null_byte(self):
        """Null byte in key_id."""
        is_valid, error = validate_policy_key("policy:SEV:key\x00")
        assert is_valid is False

    def test_invalid_backslash_in_key_id(self):
        """Backslash in key_id."""
        is_valid, error = validate_policy_key("policy:SEV:my\\key")
        assert is_valid is False

    def test_invalid_semicolon_in_key_id(self):
        """Semicolon in key_id."""
        is_valid, error = validate_policy_key("policy:SEV:my;key")
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
