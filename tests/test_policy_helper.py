#
# TEE Attestation Service - Test for policy_helper.py
#
# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This module provides comprehensive unit tests for policy_helper.py, including:
# - verify_policy_signature: Testing RSA signature verification with PSS/PKCS1v15 padding
#   including edge cases, error handling, and multi-key scenarios
#

import base64
import json
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from tas.policy_helper import verify_policy_signature


class TestVerifyPolicySignature:
    """Test cases for verify_policy_signature function."""

    @pytest.fixture
    def rsa_key_pair(self):
        """Generate RSA key pair for testing."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        return private_key, public_key

    @pytest.fixture
    def sample_policy_data(self):
        """Policy with signed_data targeting only validation_rules."""
        return {
            "metadata": {"name": "Test Policy", "version": "1.0"},
            "validation_rules": {
                "measurement": {"exact_match": "12ab34cd56ef"},
                "version": {"min_value": 3},
                "vmpl": {"exact_match": 0},
                "debug": False,
            },
            "signature": {
                "algorithm": "SHA384",
                "padding": "PSS",
                "value": "",
                "signed_data": "validation_rules",
            },
        }

    @pytest.fixture
    def default_signed_policy_data(self):
        """Policy without signed_data — signature covers all fields."""
        return {
            "metadata": {"name": "Test Policy", "version": "1.0"},
            "validation_rules": {
                "measurement": {"exact_match": "12ab34cd56ef"},
                "version": {"min_value": 3},
            },
            "signature": {"algorithm": "SHA384", "padding": "PSS", "value": ""},
        }

    @pytest.fixture
    def multi_signed_policy_data(self):
        """Policy with signed_data as a list of multiple fields."""
        return {
            "metadata": {"name": "Test Policy", "version": "1.0"},
            "validation_rules": {
                "measurement": {"exact_match": "12ab34cd56ef"},
            },
            "signature": {
                "algorithm": "SHA384",
                "padding": "PSS",
                "value": "",
                "signed_data": ["metadata", "validation_rules"],
            },
        }

    def create_valid_signature(self, policy_data, private_key, padding_scheme="PSS"):
        """Helper method to create a valid signature for test data."""
        from tas.policy_helper import canonicalize_policy

        signed_data_spec = policy_data.get("signature", {}).get("signed_data")

        if signed_data_spec is not None:
            if isinstance(signed_data_spec, str):
                signed_data_spec = [signed_data_spec]
            data_to_sign = {k: policy_data[k] for k in signed_data_spec}
        else:
            data_to_sign = policy_data

        data_json = canonicalize_policy(data_to_sign)

        # Create signature
        if padding_scheme == "PSS":
            signature = private_key.sign(
                data_json,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA384()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA384(),
            )
        else:  # PKCS1v15
            signature = private_key.sign(
                data_json,
                padding.PKCS1v15(),
                hashes.SHA384(),
            )

        return base64.b64encode(signature).decode("utf-8")

    def test_verify_valid_signature_pss(self, rsa_key_pair, sample_policy_data):
        """Test verification of valid PSS signature."""
        private_key, public_key = rsa_key_pair

        # Create valid signature
        signature_b64 = self.create_valid_signature(
            sample_policy_data, private_key, "PSS"
        )
        sample_policy_data["signature"]["value"] = signature_b64
        sample_policy_data["signature"]["padding"] = "PSS"

        public_keys = [("RSA", "test_key.pem", public_key)]

        result = verify_policy_signature(sample_policy_data, public_keys)
        assert result is True

    def test_verify_valid_signature_pkcs1v15(self, rsa_key_pair, sample_policy_data):
        """Test verification of valid PKCS1v15 signature."""
        private_key, public_key = rsa_key_pair

        # Create valid signature
        signature_b64 = self.create_valid_signature(
            sample_policy_data, private_key, "PKCS1v15"
        )
        sample_policy_data["signature"]["value"] = signature_b64
        sample_policy_data["signature"]["padding"] = "PKCS1v15"

        public_keys = [("RSA", "test_key.pem", public_key)]

        result = verify_policy_signature(sample_policy_data, public_keys)
        assert result is True

    def test_verify_invalid_signature(self, rsa_key_pair, sample_policy_data):
        """Test verification of invalid signature."""
        _, public_key = rsa_key_pair

        # Use invalid signature
        sample_policy_data["signature"]["value"] = base64.b64encode(
            b"invalid_signature"
        ).decode("utf-8")

        public_keys = [("RSA", "test_key.pem", public_key)]

        result = verify_policy_signature(sample_policy_data, public_keys)
        assert result is False

    def test_verify_multiple_keys_first_succeeds(self, sample_policy_data):
        """Test verification with multiple keys where first key succeeds."""
        # Generate two key pairs
        private_key1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key1 = private_key1.public_key()

        private_key2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key2 = private_key2.public_key()

        # Create signature with first key
        signature_b64 = self.create_valid_signature(sample_policy_data, private_key1)
        sample_policy_data["signature"]["value"] = signature_b64

        public_keys = [
            ("RSA", "key1.pem", public_key1),
            ("RSA", "key2.pem", public_key2),
        ]

        result = verify_policy_signature(sample_policy_data, public_keys)
        assert result is True

    def test_verify_multiple_keys_second_succeeds(self, sample_policy_data):
        """Test verification with multiple keys where second key succeeds."""
        # Generate two key pairs
        private_key1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key1 = private_key1.public_key()

        private_key2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key2 = private_key2.public_key()

        # Create signature with second key
        signature_b64 = self.create_valid_signature(sample_policy_data, private_key2)
        sample_policy_data["signature"]["value"] = signature_b64

        public_keys = [
            ("RSA", "key1.pem", public_key1),
            ("RSA", "key2.pem", public_key2),
        ]

        result = verify_policy_signature(sample_policy_data, public_keys)
        assert result is True

    def test_verify_multiple_keys_none_succeed(self, sample_policy_data):
        """Test verification with multiple keys where none succeed."""
        # Generate three different key pairs
        private_key1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key1 = private_key1.public_key()

        private_key2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key2 = private_key2.public_key()

        private_key3 = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Create signature with third key (not in public_keys list)
        signature_b64 = self.create_valid_signature(sample_policy_data, private_key3)
        sample_policy_data["signature"]["value"] = signature_b64

        public_keys = [
            ("RSA", "key1.pem", public_key1),
            ("RSA", "key2.pem", public_key2),
        ]

        result = verify_policy_signature(sample_policy_data, public_keys)
        assert result is False

    def test_missing_signature_section(self, rsa_key_pair):
        """Test verification when signature section is missing."""
        _, public_key = rsa_key_pair

        policy_data = {
            "validation_rules": {
                "measurement": {"exact_match": "12ab34cd56ef"},
                "version": {"min_value": 3},
                "vmpl": {"exact_match": 0},
                "debug": False,
            }
        }

        public_keys = [("RSA", "test_key.pem", public_key)]

        result = verify_policy_signature(policy_data, public_keys)
        assert result is False

    def test_missing_signature_value(self, rsa_key_pair):
        """Test verification when signature value is missing."""
        _, public_key = rsa_key_pair

        policy_data = {
            "validation_rules": {
                "measurement": {"exact_match": "12ab34cd56ef"},
                "version": {"min_value": 3},
                "vmpl": {"exact_match": 0},
                "debug": False,
            },
            "signature": {"algorithm": "SHA384", "padding": "PSS"},
        }

        public_keys = [("RSA", "test_key.pem", public_key)]

        result = verify_policy_signature(policy_data, public_keys)
        assert result is False

    def test_invalid_base64_signature(self, rsa_key_pair, sample_policy_data):
        """Test verification with invalid base64 signature."""
        _, public_key = rsa_key_pair

        sample_policy_data["signature"]["value"] = "invalid_base64!"

        public_keys = [("RSA", "test_key.pem", public_key)]

        result = verify_policy_signature(sample_policy_data, public_keys)
        assert result is False

    def test_empty_public_keys_list(self, sample_policy_data):
        """Test verification with empty public keys list."""
        sample_policy_data["signature"]["value"] = base64.b64encode(
            b"some_signature"
        ).decode("utf-8")

        public_keys = []

        result = verify_policy_signature(sample_policy_data, public_keys)
        assert result is False

    def test_data_modification_breaks_signature(self, rsa_key_pair, sample_policy_data):
        """Test that modifying validation rules breaks signature verification."""
        private_key, public_key = rsa_key_pair

        # Create valid signature
        signature_b64 = self.create_valid_signature(sample_policy_data, private_key)
        sample_policy_data["signature"]["value"] = signature_b64

        # Modify validation rules after signing
        sample_policy_data["validation_rules"]["debug"] = True

        public_keys = [("RSA", "test_key.pem", public_key)]

        result = verify_policy_signature(sample_policy_data, public_keys)
        assert result is False

    @patch("tas.policy_helper.logger")
    def test_logging_calls(self, mock_logger, rsa_key_pair, sample_policy_data):
        """Test that appropriate logging calls are made."""
        private_key, public_key = rsa_key_pair

        # Create valid signature
        signature_b64 = self.create_valid_signature(sample_policy_data, private_key)
        sample_policy_data["signature"]["value"] = signature_b64

        public_keys = [("RSA", "test_key.pem", public_key)]

        verify_policy_signature(sample_policy_data, public_keys)

        # Verify that logging methods were called
        mock_logger.info.assert_called()
        mock_logger.debug.assert_called()

    def test_exception_handling(self, sample_policy_data):
        """Test that exceptions during verification are handled gracefully."""
        # Create a mock public key that raises an exception
        mock_public_key = MagicMock()
        mock_public_key.verify.side_effect = Exception("Test exception")

        sample_policy_data["signature"]["value"] = base64.b64encode(
            b"test_signature"
        ).decode("utf-8")

        public_keys = [("RSA", "test_key.pem", mock_public_key)]

        result = verify_policy_signature(sample_policy_data, public_keys)
        assert result is False

    def test_consistent_data_serialization(self, rsa_key_pair):
        """Test that the same validation rules produce the same serialized data."""
        private_key, public_key = rsa_key_pair

        # Create two identical policy data structures with different ordering
        policy_data1 = {
            "validation_rules": {
                "measurement": {"exact_match": "12ab34cd56ef"},
                "version": {"min_value": 3},
                "vmpl": {"exact_match": 0},
                "debug": False,
            },
            "signature": {"algorithm": "SHA384", "padding": "PSS", "value": ""},
        }

        policy_data2 = {
            "validation_rules": {
                "vmpl": {"exact_match": 0},
                "debug": False,
                "measurement": {"exact_match": "12ab34cd56ef"},
                "version": {"min_value": 3},
            },
            "signature": {"algorithm": "SHA384", "padding": "PSS", "value": ""},
        }

        # Create signature for first policy
        signature_b64 = self.create_valid_signature(policy_data1, private_key)
        policy_data1["signature"]["value"] = signature_b64
        policy_data2["signature"]["value"] = signature_b64

        public_keys = [("RSA", "test_key.pem", public_key)]

        # Both should verify successfully due to consistent sorting
        result1 = verify_policy_signature(policy_data1, public_keys)
        result2 = verify_policy_signature(policy_data2, public_keys)

        assert result1 is True
        assert result2 is True

    def test_default_signs_all_fields(self, rsa_key_pair, default_signed_policy_data):
        """Test that without signed_data, signature covers all fields except signature."""
        private_key, public_key = rsa_key_pair

        signature_b64 = self.create_valid_signature(
            default_signed_policy_data, private_key
        )
        default_signed_policy_data["signature"]["value"] = signature_b64

        public_keys = [("RSA", "test_key.pem", public_key)]
        result = verify_policy_signature(default_signed_policy_data, public_keys)
        assert result is True

    def test_default_metadata_change_breaks_signature(
        self, rsa_key_pair, default_signed_policy_data
    ):
        """Test that modifying metadata breaks signature when no signed_data specified."""
        private_key, public_key = rsa_key_pair

        signature_b64 = self.create_valid_signature(
            default_signed_policy_data, private_key
        )
        default_signed_policy_data["signature"]["value"] = signature_b64

        # Modify metadata after signing
        default_signed_policy_data["metadata"]["version"] = "2.0"

        public_keys = [("RSA", "test_key.pem", public_key)]
        result = verify_policy_signature(default_signed_policy_data, public_keys)
        assert result is False

    def test_signed_data_single_field_string(self, rsa_key_pair, sample_policy_data):
        """Test signed_data as a single string field name."""
        private_key, public_key = rsa_key_pair

        signature_b64 = self.create_valid_signature(sample_policy_data, private_key)
        sample_policy_data["signature"]["value"] = signature_b64

        public_keys = [("RSA", "test_key.pem", public_key)]
        result = verify_policy_signature(sample_policy_data, public_keys)
        assert result is True

    def test_signed_data_allows_metadata_change(self, rsa_key_pair, sample_policy_data):
        """Test that with signed_data=validation_rules, changing metadata does not break sig."""
        private_key, public_key = rsa_key_pair

        signature_b64 = self.create_valid_signature(sample_policy_data, private_key)
        sample_policy_data["signature"]["value"] = signature_b64

        # Modify metadata after signing - should NOT break signature
        sample_policy_data["metadata"]["version"] = "2.0"

        public_keys = [("RSA", "test_key.pem", public_key)]
        result = verify_policy_signature(sample_policy_data, public_keys)
        assert result is True

    def test_signed_data_list_of_fields(self, rsa_key_pair, multi_signed_policy_data):
        """Test signed_data as a list of multiple field names."""
        private_key, public_key = rsa_key_pair

        signature_b64 = self.create_valid_signature(
            multi_signed_policy_data, private_key
        )
        multi_signed_policy_data["signature"]["value"] = signature_b64

        public_keys = [("RSA", "test_key.pem", public_key)]
        result = verify_policy_signature(multi_signed_policy_data, public_keys)
        assert result is True

    def test_signed_data_missing_field(self, rsa_key_pair):
        """Test that signed_data referencing a missing field returns False."""
        _, public_key = rsa_key_pair

        policy_data = {
            "validation_rules": {
                "measurement": {"exact_match": "12ab34cd56ef"},
            },
            "signature": {
                "algorithm": "SHA384",
                "padding": "PSS",
                "value": base64.b64encode(b"test").decode("utf-8"),
                "signed_data": "nonexistent_field",
            },
        }

        public_keys = [("RSA", "test_key.pem", public_key)]
        result = verify_policy_signature(policy_data, public_keys)
        assert result is False
