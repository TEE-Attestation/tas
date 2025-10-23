#
# TEE Attestation Service - KMIP JSON Client Module
#
# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This module provides a client that interacts with a KMIP server
# using JSON TTLV.
#

from __future__ import annotations

import base64
import configparser
import json
import logging
from typing import Any, Dict, List, Optional

import requests

LOGGER = logging.getLogger("tas.kmip.json.client")


# ----- Low-level helpers -----
def _enum(tag: str, value: str) -> Dict[str, Any]:
    return {"tag": tag, "type": "Enumeration", "value": value}


def _int(tag: str, value: int) -> Dict[str, Any]:
    return {"tag": tag, "type": "Integer", "value": value}


def _text(tag: str, value: str) -> Dict[str, Any]:
    return {"tag": tag, "type": "TextString", "value": value}


def _bytes(tag: str, raw: bytes) -> Dict[str, Any]:
    return {"tag": tag, "type": "ByteString", "value": base64.b64encode(raw).decode()}


def _structure(tag: str, children: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"tag": tag, "value": children}


def _bytes_hex(tag: str, raw: bytes) -> Dict[str, Any]:
    return {"tag": tag, "type": "ByteString", "value": raw.hex().upper()}


def _bool(tag: str, value: bool) -> Dict[str, Any]:
    return {"tag": tag, "type": "Boolean", "value": value}


# ----- KMIP RequestMessage Wrapper Helpers -----


def _protocol_version(major: int, minor: int) -> Dict[str, Any]:
    return _structure(
        "ProtocolVersion",
        [
            _int("ProtocolVersionMajor", major),
            _int("ProtocolVersionMinor", minor),
        ],
    )


def _request_header(
    batch_count: int,
    version: tuple[int, int],
    vendor_identification: Optional[str] = None,
) -> Dict[str, Any]:
    """Build the RequestHeader structure."""
    major, minor = version
    children: List[Dict[str, Any]] = [_protocol_version(major, minor)]
    if vendor_identification:
        children.append(_text("VendorIdentification", vendor_identification))
    children.append(_int("BatchCount", batch_count))
    return _structure("RequestHeader", children)


def wrap_in_request_message(
    operation_payloads: List[Dict[str, Any]],
    version: tuple[int, int] = (2, 1),
    vendor_identification: str = "TasKmipJsonClient",
) -> Dict[str, Any]:
    """
    Wraps one or more operation payloads into a standard KMIP RequestMessage.
    """
    batch_items = []
    for payload in operation_payloads:
        operation_name = payload.get("tag")
        if not operation_name:
            continue
        # The payload for a BatchItem is the 'value' of the original operation
        request_payload_content = payload.get("value", [])
        batch_item = _structure(
            "BatchItem",
            [
                _enum("Operation", operation_name),
                _structure("RequestPayload", request_payload_content),
            ],
        )
        batch_items.append(batch_item)

    return {
        "tag": "RequestMessage",
        "type": "Structure",
        "value": [
            _request_header(
                batch_count=len(batch_items),
                version=version,
                vendor_identification=vendor_identification,
            ),
            *batch_items,
        ],
    }


# Vendor extension Attribute
def _vendor_attribute(
    vendor_identification: str, name: str, value: Any
) -> Dict[str, Any]:
    if not isinstance(value, str):
        value = json.dumps(value)
    return {
        "tag": "Attribute",
        "value": [
            _text("VendorIdentification", vendor_identification),
            _text("AttributeName", name),
            _text("AttributeValue", value),
        ],
    }


def _find_tag_value(response_payload: Dict[str, Any], target_tag: str) -> Optional[Any]:
    """
    Performs an iterative depth-first search to find the value of a specific tag.
    """
    stack = [response_payload]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if node.get("tag") == target_tag:
                return node.get("value")
            value_child = node.get("value")
            if isinstance(value_child, (list, dict)):
                stack.append(value_child)
        elif isinstance(node, list):
            stack.extend(reversed(node))
    return None


def _extract_encryption_dict(response_json: dict) -> dict:
    """
    Extracts Data, IV, and Tag from a ResponsePayload.

        This avoids a deep recursive search by directly iterating the top-level
        'value' list, which is effective for this flat response structure.

        Args:
            response_json: The parsed JSON response from the server.

        Returns:
            A dictionary containing the values for 'Data', 'IVCounterNonce',
            and 'AuthenticatedEncryptionTag'. Returns empty dict if response
            tag is not 'ResponsePayload'.
    """
    if response_json.get("tag") != "ResponsePayload":
        return {}

    # Using a dictionary comprehension for a concise, single pass
    return {
        item["tag"]: item["value"]
        for item in response_json.get("value", [])
        if isinstance(item, dict)
        and item.get("tag") in {"Data", "IVCounterNonce", "AuthenticatedEncryptionTag"}
    }


# ----- CREATE request builder (matches request.json schema) -----
def build_create_request(
    *,
    object_type: str = "SymmetricKey",
    cryptographic_algorithm: str = "AES",
    cryptographic_length: int = 256,
    cryptographic_usage_mask: int = 2108,  # matches sample (2108)
    key_format_type: str = "TransparentSymmetricKey",
    tags: Optional[List[str]] = None,
    vendor_identification: str = "cosmian",
) -> Dict[str, Any]:
    """
    Build a KMIP Create request JSON exactly like the provided valid sample.

    Structure:
    {
      "tag": "Create",
      "value": [
        {ObjectType Enumeration},
        {
          "tag": "Attributes",
          "value": [
             ... Attribute entries and vendor extension Attribute
          ]
        }
      ]
    }
    """
    attr_list: List[Dict[str, Any]] = [
        _enum("CryptographicAlgorithm", cryptographic_algorithm),
        _int("CryptographicLength", cryptographic_length),
        _int("CryptographicUsageMask", cryptographic_usage_mask),
        _enum("KeyFormatType", key_format_type),
        _enum("ObjectType", object_type),
    ]
    if tags:
        attr_list.append(_vendor_attribute(vendor_identification, "tag", tags))

    request = {
        "tag": "Create",
        "value": [
            _enum("ObjectType", object_type),
            _structure("Attributes", attr_list),
        ],
    }
    return request


# ----- IMPORT (RSA Public Key) request builder -----
def build_import_rsa_public_key_request(
    public_key_der: bytes,
    *,
    unique_identifier: str = "",
    replace_existing: bool = False,
    usage_mask: int = 2097152,
    tags: Optional[List[str]] = None,
    vendor_identification: str = "cosmian",
) -> Dict[str, Any]:
    """
    Build an Import request for a PKCS#1 DER RSA public key matching Cosmian schema.

    Structure (example):
    {
      "tag": "Import",
      "value": [
        { "tag": "UniqueIdentifier", "type": "TextString", "value": "" },
        { "tag": "ObjectType", "type": "Enumeration", "value": "PublicKey" },
        { "tag": "ReplaceExisting", "type": "Boolean", "value": false },
        {
          "tag": "Attributes",
          "value": [
            { "tag": "CryptographicUsageMask", "type": "Integer", "value": 2097152 },
            { "tag": "Attribute", "value": [ VendorIdentification, AttributeName=tag, AttributeValue="[]" ] }
          ]
        },
        {
          "tag": "PublicKey",
          "value": [
            { "tag": "KeyBlock", "value": [
                { "tag": "KeyFormatType", "type": "Enumeration", "value": "PKCS1" },
                { "tag": "KeyValue", "value": [
                    { "tag": "KeyMaterial", "type": "ByteString", "value": "<HEX DER>" }
                ]}
            ]}
          ]
        }
      ]
    }
    """
    attr_list: List[Dict[str, Any]] = [
        _int("CryptographicUsageMask", usage_mask),
    ]
    if tags is not None:
        attr_list.append(_vendor_attribute(vendor_identification, "tag", tags))
    else:
        # Always include vendor attribute with empty list (matches rsa_import sample)
        attr_list.append(_vendor_attribute(vendor_identification, "tag", []))

    request = {
        "tag": "Import",
        "value": [
            _text("UniqueIdentifier", unique_identifier),
            _enum("ObjectType", "PublicKey"),
            _bool("ReplaceExisting", replace_existing),
            _structure("Attributes", attr_list),
            _structure(
                "PublicKey",
                [
                    _structure(
                        "KeyBlock",
                        [
                            _enum("KeyFormatType", "PKCS1"),
                            _structure(
                                "KeyValue",
                                [
                                    _bytes_hex("KeyMaterial", public_key_der),
                                ],
                            ),
                        ],
                    )
                ],
            ),
        ],
    }
    return request


# ----- IMPORT (SecretData: Password) request builder -----
def build_import_secret_data_request(
    *,
    password: str,
    unique_identifier: str,
    replace_existing: bool = False,
    usage_mask: int = 1051136,
    outer_tags: Optional[List[str]] = None,  # corresponds to AttributeValue "[]"
    inner_tags: Optional[List[str]] = None,  # corresponds to AttributeValue ["_sd"]
    vendor_identification: str = "tas",
    secret_data_type: str = "Password",
    key_format_type: str = "Raw",
) -> Dict[str, Any]:
    """
    Build an Import request for SecretData (Password) matching create_secret_data.json.

    Schema (simplified):
    {
      "tag": "Import",
      "value": [
        UniqueIdentifier (TextString, may be empty),
        ObjectType=SecretData (Enumeration),
        ReplaceExisting (Boolean),
        Attributes {
            CryptographicUsageMask (Integer),
            KeyFormatType (Enumeration),
            ObjectType (Enumeration),
            UniqueIdentifier (TextString),
            Attribute (VendorIdentification/tag -> JSON list, usually [])
        },
        SecretData {
            SecretDataType (Enumeration),
            KeyBlock {
                KeyFormatType (Enumeration),
                KeyValue {
                    KeyMaterial (ByteString HEX of raw password bytes),
                    Attributes { ... duplicated set ... vendor tag usually ["_sd"] }
                }
            }
        }
      ]
    }
    """
    # Outer Attributes list
    outer_attr_list: List[Dict[str, Any]] = [
        _int("CryptographicUsageMask", usage_mask),
        _enum("KeyFormatType", key_format_type),
        _enum("ObjectType", "SecretData"),
        _text("UniqueIdentifier", unique_identifier),
        _vendor_attribute(vendor_identification, "tag", outer_tags or []),
    ]

    # Inner (KeyValue -> Attributes) list
    inner_attr_list: List[Dict[str, Any]] = [
        _int("CryptographicUsageMask", usage_mask),
        _enum("KeyFormatType", key_format_type),
        _enum("ObjectType", "SecretData"),
        _text("UniqueIdentifier", unique_identifier),
        _vendor_attribute(vendor_identification, "tag", inner_tags or ["_sd"]),
    ]

    request = {
        "tag": "Import",
        "value": [
            _text("UniqueIdentifier", ""),  # matches sample (empty at top-level)
            _enum("ObjectType", "SecretData"),
            _bool("ReplaceExisting", replace_existing),
            _structure("Attributes", outer_attr_list),
            _structure(
                "SecretData",
                [
                    _enum("SecretDataType", secret_data_type),
                    _structure(
                        "KeyBlock",
                        [
                            _enum("KeyFormatType", key_format_type),
                            _structure(
                                "KeyValue",
                                [
                                    _bytes_hex("KeyMaterial", password.encode("utf-8")),
                                    _structure("Attributes", inner_attr_list),
                                ],
                            ),
                        ],
                    ),
                ],
            ),
        ],
    }
    return request


# ----- GET (wrapped SecretData) request builder -----
def build_get_wrapped_secret_data_request(
    *,
    secret_unique_identifier: str,
    wrapping_key_unique_identifier: str,
    wrapping_method: str = "Encrypt",
    block_cipher_mode: str = "GCM",
    cryptographic_algorithm: str = "AES",
    encoding_option: str = "NoEncoding",
) -> Dict[str, Any]:
    """
    Build a KMIP Get request that wraps (encrypts) SecretData using an existing AES key.

    Schema (matches wrap-secret-data.json):
    {
      "tag": "Get",
      "value": [
        { "tag": "UniqueIdentifier", "type": "TextString", "value": "<secret UUID>" },
        {
          "tag": "KeyWrappingSpecification",
          "value": [
            { "tag": "WrappingMethod", "type": "Enumeration", "value": "Encrypt" },
            {
              "tag": "EncryptionKeyInformation",
              "value": [
                { "tag": "UniqueIdentifier", "type": "TextString", "value": "<aes key UUID>" },
                {
                  "tag": "CryptographicParameters",
                  "value": [
                    { "tag": "BlockCipherMode", "type": "Enumeration", "value": "GCM" },
                    { "tag": "CryptographicAlgorithm", "type": "Enumeration", "value": "AES" }
                  ]
                }
              ]
            },
            { "tag": "EncodingOption", "type": "Enumeration", "value": "NoEncoding" }
          ]
        }
      ]
    }
    """
    return {
        "tag": "Get",
        "value": [
            _text("UniqueIdentifier", secret_unique_identifier),
            _structure(
                "KeyWrappingSpecification",
                [
                    _enum("WrappingMethod", wrapping_method),
                    _structure(
                        "EncryptionKeyInformation",
                        [
                            _text("UniqueIdentifier", wrapping_key_unique_identifier),
                            _structure(
                                "CryptographicParameters",
                                [
                                    _enum("BlockCipherMode", block_cipher_mode),
                                    _enum(
                                        "CryptographicAlgorithm",
                                        cryptographic_algorithm,
                                    ),
                                ],
                            ),
                        ],
                    ),
                    _enum("EncodingOption", encoding_option),
                ],
            ),
        ],
    }


# ----- GET (SecretData / Key / Object) as-registered request builder -----
def build_get_secret_as_registered_request(
    unique_identifier: str,
    key_wrap_type: str = "AsRegistered",
) -> Dict[str, Any]:
    """
    Build a KMIP Get request that retrieves an object (e.g. SecretData) by
    UniqueIdentifier with KeyWrapType=AsRegistered, matching get.json schema:

    {
      "tag": "Get",
      "value": [
        { "tag": "UniqueIdentifier", "type": "TextString", "value": "<uuid>" },
        { "tag": "KeyWrapType", "type": "Enumeration", "value": "AsRegistered" }
      ]
    }
    """
    return {
        "tag": "Get",
        "value": [
            _text("UniqueIdentifier", unique_identifier),
            _enum("KeyWrapType", key_wrap_type),
        ],
    }


def build_encrypt_aes_gcm_request(
    *,
    unique_identifier: str,
    plaintext: bytes,
) -> Dict[str, Any]:
    """
    Build an AES-GCM Encrypt request matching aes-gcm.json.
    JSON shape:
    {
      "tag": "Encrypt",
      "value": [
        { "tag": "UniqueIdentifier", "type": "TextString", "value": "<key UUID>" },
        {
          "tag": "CryptographicParameters",
          "value": [
            { "tag": "BlockCipherMode", "type": "Enumeration", "value": "GCM" },
            { "tag": "CryptographicAlgorithm", "type": "Enumeration", "value": "AES" }
          ]
        },
        { "tag": "Data", "type": "ByteString", "value": "<PLAINTEXT HEX>" }
      ]
    }
    """
    return {
        "tag": "Encrypt",
        "value": [
            _text("UniqueIdentifier", unique_identifier),
            _structure(
                "CryptographicParameters",
                [
                    _enum("BlockCipherMode", "GCM"),
                    _enum("CryptographicAlgorithm", "AES"),
                ],
            ),
            _bytes_hex("Data", plaintext),
        ],
    }


def _get_response_payload(response_message: dict) -> dict:
    """
    Validates a KMIP ResponseMessage and extracts the ResponsePayload.

    This function performs the following checks:
    1. Confirms the top-level tag is 'ResponseMessage'.
    2. Finds the first 'BatchItem'.
    3. Checks the 'ResultStatus' within the BatchItem.
    4. If the status is 'Success', it returns the contents of the 'ResponsePayload'.
    5. If the status is not 'Success', it raises a RuntimeError with details
       from 'ResultReason' and 'ResultMessage'.

    Args:
        response_message: The parsed JSON of a KMIP ResponseMessage.

    Returns:
        The dictionary representing the core response (e.g., the contents
        of a CreateResponse) if the operation was successful.

    Raises:
        ValueError: If the response is not a valid or expected ResponseMessage structure.
        RuntimeError: If the KMIP operation failed.
    """
    if (
        not isinstance(response_message, dict)
        or response_message.get("tag") != "ResponseMessage"
    ):
        raise ValueError(
            f"Invalid input: Expected a dictionary with tag 'ResponseMessage', got tag '{response_message.get('tag')}'"
        )

    # Find the first BatchItem in the response
    batch_item = next(
        (
            item
            for item in response_message.get("value", [])
            if item.get("tag") == "BatchItem"
        ),
        None,
    )

    if not batch_item:
        raise ValueError("ResponseMessage contains no BatchItem")

    # Efficiently extract key-value pairs from the BatchItem's contents
    batch_results = {
        item["tag"]: item
        for item in batch_item.get("value", [])
        if isinstance(item, dict) and "tag" in item
    }

    result_status = batch_results.get("ResultStatus", {}).get("value")

    if result_status == "Success":
        response_payload = batch_results.get("ResponsePayload")
        if response_payload is None:
            raise ValueError(
                "Operation was successful, but no ResponsePayload was found"
            )
        # The payload itself is a structure containing the actual response objects.
        return response_payload

    # Handle failure
    reason = batch_results.get("ResultReason", {}).get("value", "No Reason Provided")
    message = batch_results.get("ResultMessage", {}).get("value", "No Message Provided")
    raise RuntimeError(
        f"KMIP operation failed. Status: {result_status}, Reason: {reason}, Message: {message}"
    )


def _get_key_material(resp: dict) -> Dict[str, Any]:
    key_hex_str = None
    if resp is None:
        raise RuntimeError("No ResponsePayload returned from KMIP server")

    if resp.get("tag") != "ResponsePayload":
        raise RuntimeError(f"Unexpected KMIP response tag: {resp.get('tag')}")

    # Traverse KMIP structure to locate KeyMaterial
    # Stack for iterative depth-first search to find KeyMaterial generically
    stack = [resp]
    key_hex_str = None

    while stack:
        node = stack.pop()

        if isinstance(node, dict):
            # Check if this is the target node
            if node.get("tag") == "KeyMaterial":
                key_hex_str = node.get("value")
                break  # Found it, exit the loop

            # If not, add its 'value' to the stack to search deeper
            value_child = node.get("value")
            if isinstance(value_child, (dict, list)):
                stack.append(value_child)

        elif isinstance(node, list):
            # Add all items from the list to the stack (in reverse to maintain order)
            stack.extend(reversed(node))

    if not key_hex_str:
        raise ValueError("KeyMaterial not found in ResponsePayload")

    return {"WrappedKeyMaterial": key_hex_str, "raw": resp}


def _get_key_value(resp: dict) -> Dict[str, Any]:
    key_hex_str = None
    if resp is None:
        raise RuntimeError("No ResponsePayload returned from KMIP server")

    if resp.get("tag") != "ResponsePayload":
        raise RuntimeError(f"Unexpected KMIP response tag: {resp.get('tag')}")

    # Traverse KMIP structure to locate KeyValue
    # Stack for iterative depth-first search to find KeyValue generically
    stack = [resp]
    key_hex_str = None

    while stack:
        node = stack.pop()

        if isinstance(node, dict):
            # Check if this is the target node
            if node.get("tag") == "KeyValue":
                key_hex_str = node.get("value")
                break  # Found it, exit the loop

            # If not, add its 'value' to the stack to search deeper
            value_child = node.get("value")
            if isinstance(value_child, (dict, list)):
                stack.append(value_child)

        elif isinstance(node, list):
            # Add all items from the list to the stack (in reverse to maintain order)
            stack.extend(reversed(node))

    if not key_hex_str:
        raise ValueError("KeyValue not found in ResponsePayload")

    return {"KeyValue": key_hex_str, "raw": resp}


# ----- DESTROY and REVOKE request builders -----


def _build_destroy_request(unique_identifier: str) -> Dict[str, Any]:
    """
    Build a KMIP Destroy request JSON.

    Structure:
    {
      "tag": "Destroy",
      "value": [
        { "tag": "UniqueIdentifier", "type": "TextString", "value": "<uuid>" }
      ]
    }
    """
    return {
        "tag": "Destroy",
        "value": [
            _text("UniqueIdentifier", unique_identifier),
        ],
    }


def _build_revoke_request(
    unique_identifier: str,
    revocation_reason_code: Optional[str] = "Unspecified",
    revocation_message: Optional[str] = "NO LONGER USED",
) -> Dict[str, Any]:
    """
    Build a KMIP Revoke request JSON including RevocationMessage.

    Structure:
    {
      "tag": "Revoke",
      "value": [
        { "tag": "UniqueIdentifier", ... },
        {
          "tag": "RevocationReason",
          "value": [
            { "tag": "RevocationReasonCode", ... },
            { "tag": "RevocationMessage", ... }
          ]
        }
      ]
    }
    """
    value_items = [_text("UniqueIdentifier", unique_identifier)]
    if revocation_reason_code:
        reason_children = [_enum("RevocationReasonCode", revocation_reason_code)]
        if revocation_message:
            reason_children.append(_text("RevocationMessage", revocation_message))
        value_items.append(_structure("RevocationReason", reason_children))

    return {
        "tag": "Revoke",
        "value": value_items,
    }


# ----- GET (wrapped by AES-GCM) request builder -----
def _build_get_wrapped_by_aes_gcm_request(
    secret_to_wrap_uid: str,
    wrapping_key_uid: str,
) -> Dict[str, Any]:
    """
    Builds a KMIP Get request to retrieve a secret object wrapped with an AES key
    using GCM mode.
    """
    return {
        "tag": "Get",
        "value": [
            _text("UniqueIdentifier", secret_to_wrap_uid),
            {
                "tag": "KeyWrappingSpecification",
                "value": [
                    _enum("WrappingMethod", "Encrypt"),
                    {
                        "tag": "EncryptionKeyInformation",
                        "value": [
                            _text("UniqueIdentifier", wrapping_key_uid),
                            {
                                "tag": "CryptographicParameters",
                                "value": [
                                    _enum("BlockCipherMode", "GCM"),
                                    _enum("CryptographicAlgorithm", "AES"),
                                ],
                            },
                        ],
                    },
                    _enum("EncodingOption", "NoEncoding"),
                ],
            },
        ],
    }


# ----- GET (wrapped by RSA) request builder -----
def _build_get_wrapped_by_rsa_request(
    *,
    key_to_wrap_uid: str,
    wrapping_key_uid: str,
    padding_method: str = "OAEP",
    hashing_algorithm: str = "SHA256",
) -> Dict[str, Any]:
    """
    Build a KMIP Get request to wrap a key with an RSA key using OAEP padding.

    Schema (matches wrap-aes-key.json):
    {
      "tag": "Get",
      "value": [
        { "tag": "UniqueIdentifier", "value": "<key_to_wrap_uid>" },
        {
          "tag": "KeyWrappingSpecification",
          "value": [
            { "tag": "WrappingMethod", "value": "Encrypt" },
            {
              "tag": "EncryptionKeyInformation",
              "value": [
                { "tag": "UniqueIdentifier", "value": "<wrapping_key_uid>" },
                {
                  "tag": "CryptographicParameters",
                  "value": [
                    { "tag": "PaddingMethod", "value": "OAEP" },
                    { "tag": "HashingAlgorithm", "value": "SHA256" },
                    { "tag": "CryptographicAlgorithm", "value": "RSA" }
                  ]
                }
              ]
            },
            { "tag": "EncodingOption", "value": "NoEncoding" }
          ]
        }
      ]
    }
    """
    crypto_params = _structure(
        "CryptographicParameters",
        [
            _enum("PaddingMethod", padding_method),
            _enum("HashingAlgorithm", hashing_algorithm),
            _enum("CryptographicAlgorithm", "RSA"),
        ],
    )

    encryption_key_info = _structure(
        "EncryptionKeyInformation",
        [
            _text("UniqueIdentifier", wrapping_key_uid),
            crypto_params,
        ],
    )

    key_wrapping_spec = _structure(
        "KeyWrappingSpecification",
        [
            _enum("WrappingMethod", "Encrypt"),
            encryption_key_info,
            _enum("EncodingOption", "NoEncoding"),
        ],
    )

    return {
        "tag": "Get",
        "value": [
            _text("UniqueIdentifier", key_to_wrap_uid),
            key_wrapping_spec,
        ],
    }


# ----- Client wrapper for sending raw schema requests -----
class KmipJsonClient:
    @classmethod
    def from_config(cls, config_path: str, section: str = "kmip") -> "KmipJsonClient":
        """
        Creates a KmipJsonClient instance from a .conf (INI-style) file.

        The config file should have a section (defaulting to [kmip]) with keys
        that match the __init__ parameters.

        Example config.conf:
        [kmip]
        base_url = https://127.0.0.1:9998
        certfile = certs/client.crt
        keyfile = certs/client.key
        ca_cert = certs/ca.crt
        verify_tls = false
        debug = true
        kmip_version = 2,1
        """
        parser = configparser.ConfigParser()
        if not parser.read(config_path):
            raise FileNotFoundError(f"Configuration file not found at {config_path}")

        if not parser.has_section(section):
            raise ValueError(f"Section '[{section}]' not found in {config_path}")

        config = dict(parser.items(section))

        # Handle type conversions from string
        if "verify_tls" in config:
            config["verify_tls"] = parser.getboolean(section, "verify_tls")
        if "debug" in config:
            config["debug"] = parser.getboolean(section, "debug")
        if "timeout" in config:
            config["timeout"] = parser.getint(section, "timeout")
        if "kmip_version" in config:
            version_str = parser.get(section, "kmip_version")
            config["kmip_version"] = tuple(map(int, version_str.split(",")))

        return cls(**config)

    def __init__(
        self,
        base_url: str,
        certfile: str,
        keyfile: str,
        ca_cert: str,
        kmip_path: str = "/kmip",  # default path
        timeout: int = 30,
        verify_tls: bool = True,
        debug: bool = False,
        vendor_identification: str = "TasKmipJsonClient",
        kmip_version: tuple[int, int] = (2, 1),
    ) -> None:
        self.endpoint = base_url.rstrip("/") + kmip_path
        self.timeout = timeout
        LOGGER.setLevel(logging.DEBUG if debug else logging.INFO)
        self.debug = debug
        self.vendor_identification = vendor_identification
        self.version = kmip_version

        # Store connection parameters
        self._cert = (certfile, keyfile)
        self._verify = ca_cert if verify_tls else False
        self.session: Optional[requests.Session] = None

    def open(self) -> None:
        """Initializes the requests.Session for connection pooling."""
        if self.session is None:
            self.session = requests.Session()
            self.session.cert = self._cert
            self.session.verify = self._verify
            self.session.headers.update(
                {"Content-Type": "application/json", "Accept": "application/json"}
            )

    def close(self) -> None:
        """Closes the underlying requests session."""
        if self.session:
            self.session.close()
            self.session = None

    def __enter__(self) -> "KmipJsonClient":
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _post(self, body: Dict[str, Any]) -> Dict[str, Any]:
        if self.session is None:
            raise RuntimeError(
                "Session is not open. Call open() or use a 'with' statement."
            )
        if self.debug:
            LOGGER.debug("KMIP Request ==> %s", json.dumps(body, indent=2))
        # Use the session object to make the POST request
        resp = self.session.post(
            self.endpoint,
            json=body,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        if self.debug:
            LOGGER.debug("KMIP Response <== %s", json.dumps(data, indent=2))
        return data

    def _post_wrapped(self, operation_payloads: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Wraps payloads in a RequestMessage and posts."""
        request_message = wrap_in_request_message(
            operation_payloads,
            version=self.version,
            vendor_identification=self.vendor_identification,
        )
        # The raw response will be a ResponseMessage
        response_message = self._post(request_message)

        # Extract the first BatchItem's payload for compatibility
        return _get_response_payload(response_message)

    def create_aes_key_kmip(
        self,
        name: Optional[str],
        length_bits: int = 256,
        vendor_identification: str = "TasKmipJsonClient",
    ) -> str:
        """create_aes_key equivalent that sends a standard RequestMessage."""
        tags = [name] if name else None
        create_payload = build_create_request(
            object_type="SymmetricKey",
            cryptographic_algorithm="AES",
            cryptographic_length=length_bits,
            cryptographic_usage_mask=2108,
            key_format_type="TransparentSymmetricKey",
            tags=tags,
            vendor_identification=vendor_identification,
        )
        resp = self._post_wrapped([create_payload])
        if resp.get("tag") != "ResponsePayload":
            raise ValueError("Unexpected response tag: " + resp.get("tag", "MISSING"))
        uid = _find_tag_value(resp, "UniqueIdentifier")
        if not uid:
            raise ValueError("UniqueIdentifier not found in response")
        return uid

    def register_rsa_public_key_kmip(
        self,
        public_key_der: bytes,
        name: Optional[str] = None,
        vendor_identification: str = "TasKmipJsonClient",
    ) -> str:
        """
        Import an RSA public key (PKCS#1 DER) into the KMIP server.
        Returns the assigned UniqueIdentifier string.
        """
        tags = [name] if name else None
        import_payload = build_import_rsa_public_key_request(
            public_key_der,
            unique_identifier="",
            replace_existing=False,
            usage_mask=2097152,
            tags=tags,
            vendor_identification=vendor_identification,
        )
        resp = self._post_wrapped([import_payload])
        if resp.get("tag") != "ResponsePayload":
            raise ValueError("Unexpected response tag: " + resp.get("tag", "MISSING"))
        uid = _find_tag_value(resp, "UniqueIdentifier")
        if not uid:
            raise ValueError("UniqueIdentifier not found in response")
        return uid

    def register_secret_password_kmip(
        self,
        password: str,
        *,
        unique_identifier: str = "",
        vendor_identification: str = "TasKmipJsonClient",
    ) -> str:
        """
        Convenience wrapper: import password, return UniqueIdentifier from response.
        """
        import_payload = build_import_secret_data_request(
            password=password,
            unique_identifier=unique_identifier,
            replace_existing=False,
            usage_mask=1051136,
            outer_tags=None,
            inner_tags=None,
            vendor_identification=vendor_identification,
        )
        resp = self._post_wrapped([import_payload])
        if resp.get("tag") != "ResponsePayload":
            raise ValueError("Unexpected response tag: " + resp.get("tag", "MISSING"))
        uid = _find_tag_value(resp, "UniqueIdentifier")
        if not uid:
            raise ValueError("UniqueIdentifier not found in response")
        return uid

    def get_secret_as_registered_bytes_kmip(
        self,
        unique_identifier: str,
    ) -> Optional[bytes]:
        """
        Return KeyMaterial as bytes (hex-decoded). Returns None if absent or invalid.
        """
        get_secret_as_registered_payload = build_get_secret_as_registered_request(
            unique_identifier=unique_identifier,
            key_wrap_type="AsRegistered",
        )
        resp = self._post_wrapped([get_secret_as_registered_payload])
        if resp.get("tag") != "ResponsePayload":
            raise ValueError("Unexpected response tag: " + resp.get("tag", "MISSING"))

        # Traverse KMIP structure to locate KeyMaterial
        hex_str = _get_key_material(resp).get("WrappedKeyMaterial")
        if not hex_str:
            raise ValueError("KeyMaterial not found in ResponsePayload")
        try:
            return bytes.fromhex(hex_str)
        except ValueError:
            return None

    def encrypt_aes_gcm_bytes_kmip(
        self,
        key_unique_identifier: str,
        plaintext: bytes,
    ) -> Dict[bytes, Any]:
        """
        Encrypt plaintext using an existing AES key (GCM mode).
        Returns ciphertext as bytes (hex-decoded) or throws an
        exception if absent/invalid.
        """

        aes_gcm_request_message = build_encrypt_aes_gcm_request(
            unique_identifier=key_unique_identifier,
            plaintext=plaintext,
        )
        resp = self._post_wrapped([aes_gcm_request_message])
        if resp.get("tag") != "ResponsePayload":
            raise ValueError("Unexpected response tag: " + resp.get("tag", "MISSING"))
        results = _extract_encryption_dict(resp)
        print("Encryption results:", results)
        # Decode hex to bytes, return None if invalid
        try:
            ciphertext_bytes = (
                bytes.fromhex(results["Data"]) if results.get("Data") else None
            )
        except ValueError:
            ciphertext_bytes = None
        try:
            iv_bytes = (
                bytes.fromhex(results["IVCounterNonce"])
                if results.get("IVCounterNonce")
                else None
            )
        except ValueError:
            iv_bytes = None
        try:
            tag_bytes = (
                bytes.fromhex(results["AuthenticatedEncryptionTag"])
                if results.get("AuthenticatedEncryptionTag")
                else None
            )
        except ValueError:
            tag_bytes = None

        if self.debug:
            print("Ciphertext bytes:", ciphertext_bytes)
            print("IV bytes:", iv_bytes)
            print("Tag bytes:", tag_bytes)

        if ciphertext_bytes is None or iv_bytes is None or tag_bytes is None:
            raise ValueError("Failed to decode encryption results to bytes")

        return {"Ciphertext": ciphertext_bytes, "IV": iv_bytes, "Tag": tag_bytes}

    def destroy_key_kmip(self, unique_identifier: str) -> str:
        """
        Destroy a managed object using a standard KMIP RequestMessage.
        Returns the UniqueIdentifier of the destroyed object on success.
        """
        destroy_payload = _build_destroy_request(unique_identifier)
        resp = self._post_wrapped([destroy_payload])

        if resp.get("tag") != "ResponsePayload":
            raise ValueError(f"Unexpected response tag: {resp.get('tag', 'MISSING')}")

        uid = _find_tag_value(resp, "UniqueIdentifier")
        if not uid:
            raise ValueError("UniqueIdentifier not found in response")
        return uid

    def revoke_key_kmip(
        self,
        unique_identifier: str,
        reason_code: Optional[str] = "Unspecified",
        message: Optional[str] = "NO LONGER USED",
    ) -> str:
        """
        Revoke a managed object using a standard KMIP RequestMessage.
        Returns the UniqueIdentifier of the revoked object on success.
        """
        revoke_payload = _build_revoke_request(unique_identifier, reason_code, message)
        resp = self._post_wrapped([revoke_payload])

        # The actual response is inside the 'value' of the ResponsePayload
        inner_payload = resp.get("value", [])

        if resp.get("tag") != "ResponsePayload":
            raise ValueError(f"Unexpected response tag: {resp.get('tag', 'MISSING')}")

        uid = _find_tag_value(resp, "UniqueIdentifier")
        if not uid:
            raise ValueError("UniqueIdentifier not found in response")
        return uid

    def get_rsa_wrapped_key_bytes_kmip(
        self,
        key_to_wrap_uid: str,
        wrapping_key_uid: str,
        padding_method: str = "OAEP",
        hashing_algorithm: str = "SHA256",
    ) -> bytes:
        """
        Retrieve a key, wrapped with an RSA key (KMIP RequestMessage).
        Returns the raw GetResponse and the extracted wrapped key material.
        """
        get_payload = _build_get_wrapped_by_rsa_request(
            key_to_wrap_uid=key_to_wrap_uid,
            wrapping_key_uid=wrapping_key_uid,
            padding_method=padding_method,
            hashing_algorithm=hashing_algorithm,
        )
        resp = self._post_wrapped([get_payload])
        if resp.get("tag") != "ResponsePayload":
            raise ValueError("Unexpected response tag: " + resp.get("tag", "MISSING"))

        # Traverse KMIP structure to locate KeyValue
        hex_str = _get_key_value(resp).get("KeyValue")
        if not hex_str:
            raise ValueError("KeyValue not found in ResponsePayload")
        try:
            return bytes.fromhex(hex_str)
        except ValueError:
            raise ValueError("Failed to decode KeyValue hex string")

    def get_secret_wrapped_by_aes_gcm_kmip(
        self, secret_to_wrap_uid: str, wrapping_key_uid: str
    ) -> Dict[str, bytes]:
        """
        Retrieves a secret object, wrapped with a specified AES key using GCM.
        The server is expected to return the IV, ciphertext, and tag concatenated
        in the KeyValue field.
        """
        get_payload = _build_get_wrapped_by_aes_gcm_request(
            secret_to_wrap_uid=secret_to_wrap_uid,
            wrapping_key_uid=wrapping_key_uid,
        )
        resp = self._post_wrapped([get_payload])

        # Find the KeyValue which contains the concatenated result
        key_value_hex = _find_tag_value(resp, "KeyValue")
        if not key_value_hex:
            raise ValueError("KeyValue not found in ResponsePayload")

        try:
            concatenated_bytes = bytes.fromhex(key_value_hex)
        except (ValueError, TypeError) as e:
            raise ValueError(f"Failed to decode KeyValue hex string: {e}")

        # Standard AES-GCM sizes: 12-byte IV, 16-byte Tag
        iv_len = 12
        tag_len = 16
        min_len = iv_len + tag_len

        if len(concatenated_bytes) < min_len:
            raise ValueError(
                f"KeyValue is too short to contain IV and Tag. "
                f"Expected at least {min_len} bytes, got {len(concatenated_bytes)}."
            )

        # Slice the concatenated bytes into iv, ciphertext, and tag
        iv = concatenated_bytes[:iv_len]
        tag_start = len(concatenated_bytes) - tag_len
        ciphertext = concatenated_bytes[iv_len:tag_start]
        tag = concatenated_bytes[tag_start:]

        return {
            "iv": iv,
            "ciphertext": ciphertext,
            "tag": tag,
        }


# ----- Script usage example -----
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    # Example using direct initialization (fill in certificate paths):
    # client_direct = KmipJsonClient(
    #     base_url="https://kmip.example.com:5696",
    #     certfile="path/to/client.crt",
    #     keyfile="path/to/client.key",
    #     ca_cert="path/to/ca.crt",
    #     debug=True,
    # )

    # Example using a .conf configuration file:
    # try:
    #     # Create a config.conf file with a [kmip] section
    #     client_from_file = KmipJsonClient.from_config("config.conf")
    #     # resp = client_from_file.create_aes_key_kmip(name="key-from-config")
    #     # print("Created key with UUID:", resp)
    # except FileNotFoundError:
    #     print("Configuration file 'config.conf' not found. Skipping file-based client creation.")
    # except Exception as e:
    #      print(f"Failed to create client from config file: {e}")

    print("KMIP minimal JSON client loaded.")
