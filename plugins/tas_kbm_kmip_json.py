#
# TEE Attestation Service - KMIP JSON Broker Module (KBM)
#
# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This module interacts with the KMIP server using JSON TTLV.
#


import base64

from plugins.kjc.kmip_json_client import KmipJsonClient
from tas.tas_logging import get_logger

# Setup logging for the KMIP plugin
logger = get_logger("tas.plugins.tas_kbm_kmip_json")


def _kbm_encode_bytes_to_base64(data: bytes) -> str:
    """
    Encodes bytes to a base64 string.

    Parameters:
        data (bytes): The bytes to encode.

    Returns:
        str: The base64 encoded string.
    """
    if not isinstance(data, bytes):
        raise ValueError("Input data must be of type bytes.")
    # Encode the bytes to utf-8 string
    return base64.b64encode(data).decode("utf-8")


def _kbm_encode_secret(wrapped_key: bytes, blob: bytes, iv: bytes, tag: bytes) -> dict:
    """
    Encodes the wrapped key, blob, and iv as a string.

    Parameters:
        wrapped_key (bytes): The wrapped key.
        blob (bytes): The encrypted secret blob.
        iv (bytes): The IV used for the encrypted secret blob.
        tag (bytes): The authentication tag for the encrypted secret blob.

    Returns:
        dict: The json representation of the wrapped key, blob, iv and tag.
    """

    # Create a dictionary with the wrapped key, blob, and iv
    data = {
        "wrapped_key": _kbm_encode_bytes_to_base64(wrapped_key),
        "blob": _kbm_encode_bytes_to_base64(blob),
        "iv": _kbm_encode_bytes_to_base64(iv),
        "tag": _kbm_encode_bytes_to_base64(tag),
    }

    return data


def _kbm_destroy_key(
    client: KmipJsonClient,
    key_id: str,
) -> None:
    """
    Destroys the key associated with the given key_id on the KMIP server.
    Parameters:
        client (MIPJsonClient): The KMIP client instance.
        key_id (str): The unique identifier of the key to destroy.
    Returns:
        None
    Raises:
        ValueError: If the destruction process fails.
    """
    logger.info(f"Destroying key with ID: {key_id}")
    try:
        # revoke the key
        logger.debug(f"Revoking key {key_id}")
        client.revoke_key_kmip(key_id)
        logger.debug(f"Successfully revoked key with ID: {key_id}")

        # Destroy the key on the KMIP server
        logger.debug(f"Destroying key {key_id}")
        client.destroy_key_kmip(key_id)
        logger.info(f"Successfully destroyed key with ID: {key_id}")
    except Exception as e:
        logger.error(f"Error destroying key {key_id}: {e}")
        raise ValueError(
            f"TAS-KBM: An error occurred while destroying the key with ID {key_id}: {e}"
        )


def _kbm_wrap_secrets(
    client: KmipJsonClient,
    secret_key_id: str,
    rsa_pub_key: bytes,
) -> tuple[bytes, bytes, bytes, bytes]:
    """
    Wraps a secret using the KMIP server.

    Parameters:
        client (KMIPJsonClient): The KMIP client instance.
        secret_key_id (str): The id of the secret to encrypt.
        rsa_pub_key (bytes): The RSA public key to wrap the secret encryption key.

    Returns:
        bytes: The wrapped key as bytes.
        bytes: The encrypted secret blob.
        bytes: The IV used for the encrypted secret blob.
        bytes: The authentication tag for the encrypted secret blob.

    Raises:
        ValueError: If the wrapping process fails.
    """
    logger.info(f"Wrapping secret for key ID: {secret_key_id}")
    try:
        # Initialize variables
        aes_key_id = None
        rsa_key_id = None
        wrapped_key = None

        # Generate a new AES secrets encryption key
        logger.debug("Creating AES encryption key for secret wrapping")
        aes_key_id = client.create_aes_key_kmip(
            length_bits=256,
            name="Temporary AES Key for Secret Wrapping",
        )
        logger.info(f"Created AES encryption key with ID: {aes_key_id}")

        # Wrap the secret with the AES key
        logger.debug("Wrapping secret with AES key")

        wrapped_obj = client.get_secret_wrapped_by_aes_gcm_kmip(
            secret_key_id, aes_key_id
        )
        ciphertext = wrapped_obj.get("ciphertext")
        iv = wrapped_obj.get("iv")
        tag = wrapped_obj.get("tag")
        if not ciphertext or not iv or not tag:
            logger.error("Failed to encrypt secret with AES key")
            raise ValueError("TAS-KBM: Failed to encrypt secret with AES key")
        logger.info(f"Encrypted secret with AES key ID: {aes_key_id}")

        # Register client's RSA public key with the KMIP server
        logger.debug("Registering client's RSA public key")
        rsa_key_id = client.register_rsa_public_key_kmip(
            public_key_der=rsa_pub_key,
            name="Client's RSA Public Key",
        )
        if not rsa_key_id:
            logger.error("Failed to register client's RSA public key")
            raise ValueError("TAS-KBM: Failed to register client's RSA public key")
        logger.info(f"Registered RSA public key with ID: {rsa_key_id}")

        # Wrap the AES key with the RSA public key
        logger.debug("Wrapping AES key with RSA public key")
        wrapped_key = client.get_rsa_wrapped_key_bytes_kmip(
            aes_key_id,
            rsa_key_id,
        )
        logger.info("Secret's AES key wrapped with client's RSA wrapping key")

    except Exception as e:
        logger.error(f"Error wrapping secret: {e}")
        raise ValueError(f"TAS-KBM: An error occurred while wrapping the secret: {e}")

    finally:
        # Destroy the AES key after wrapping
        if aes_key_id:
            logger.debug(f"Cleaning up AES key: {aes_key_id}")
            _kbm_destroy_key(client, aes_key_id)
            logger.debug(f"Destroyed AES key with ID: {aes_key_id}")
        # Destroy the RSA key after wrapping
        if rsa_key_id:
            logger.debug(f"Cleaning up RSA key: {rsa_key_id}")
            _kbm_destroy_key(client, rsa_key_id)
            logger.debug(f"Destroyed RSA key with ID: {rsa_key_id}")

    logger.info(f"Successfully wrapped secret for key ID: {secret_key_id}")
    return wrapped_key, ciphertext, iv, tag


def kbm_open_client_connection(config_file="./config/kmipjson/kmip.conf"):
    """
    Opens a connection to the KMIP server using the TAS KMIPJsonClient.

    Parameters:
        config_file (str): Path to the KMIPJsonClient configuration file.

    Returns:
        KMIPJsonClient: An instance of the connected KMIP client.

    Raises:
        RuntimeError: If the connection to the KMIP server fails.
    """
    logger.info(f"Initializing KMIP client connection with config: {config_file}")
    try:
        # Initialize the KMIP client with the specified configuration file
        kmip_client = KmipJsonClient.from_config(config_path=config_file)
        if not kmip_client:
            logger.error("Failed to initialize KMIP client")
            raise RuntimeError("TAS-KBM: Failed to initialize KMIP client")
        logger.info("KMIP client initialized successfully")
        # Open the connection to the KMIP server
        logger.debug("Opening connection to KMIP server")
        kmip_client.open()
        logger.info("Successfully connected to the KMIP server.")

        return kmip_client

    except Exception as e:
        logger.error(f"Failed to connect to KMIP server: {e}")
        raise RuntimeError(f"TAS-KBM: Failed to connect to the KMIP server: {e}")


def kbm_close_client_connection(kmip_client):
    """
    Closes the connection to the KMIP server.

    Parameters:
        kmip_client (KmipJsonClient): The KMIP client instance to close.

    Returns:
        None
    """
    logger.info("Closing KMIP client connection")
    try:
        # Close the connection to the KMIP server
        kmip_client.close()
        logger.info("Successfully closed the connection to the KMIP server.")
    except Exception as e:
        logger.error(f"Failed to close KMIP connection: {e}")
        raise RuntimeError(
            f"TAS-KBM: Failed to close the connection to the KMIP server: {e}"
        )


def kbm_get_secret(
    kmip_client: KmipJsonClient, key_id: str, wrapping_key: bytes
) -> dict:
    """
    Retrieve the secret associated with the given key_id from the KMIP server.

    Parameters:
        key_id (str): The unique identifier of the secret to retrieve.
        wrapping_key (bytes): The wrapping key used to encrypt the secret.
        kmip_client (KMIPJsonClient): The KMIP client instance.

    Returns:
        dict: The secret as a jsonfiable dictionary.

    Raises:
        ValueError: If the retrieval process fails.
        RuntimeError: If the KMIP server connection fails.
    """
    logger.info(f"KMIP get_secret request for key_id: {key_id}")

    try:
        wrapped_key, blob, iv, tag = _kbm_wrap_secrets(
            kmip_client,
            key_id,
            wrapping_key,
        )
        if not wrapped_key or not blob or not iv or not tag:
            logger.error(f"Failed to retrieve/wrap secret for Key ID: {key_id}")
            raise ValueError(f"TAS-KBM: Failed to retrieve secret for Key ID: {key_id}")

        # Encode secret payload as base64 string in a python dictionary
        logger.debug("Encoding wrapped secret as base64")
        secret = _kbm_encode_secret(
            wrapped_key,
            blob,
            iv,
            tag,
        )
        if not secret:
            logger.error(f"Failed to encode secret for Key ID: {key_id}")
            raise ValueError(
                f"TAS-KBM: Failed to retrieve and encode secret for Key ID: {key_id}"
            )

    except Exception as e:
        logger.error(f"Error retrieving secret for Key ID {key_id}: {e}")
        raise ValueError(
            f"TAS-KBM: An error occurred while retrieving the secret for Key ID {key_id}: {e}"
        )

    logger.info(f"Retrieved secret for Key ID {key_id}")

    # Return the base64 encoded secret
    return secret


__all__ = [
    "kbm_open_client_connection",
    "kbm_close_client_connection",
    "kbm_get_secret",
]
