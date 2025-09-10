#
# TEE Attestation Service - KMIP Broker Module (KBM)
#
# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# This file is part of the TEE Attestation Service.
#
# This module interacts with the KMIP server.
#

# This is need to avoid the error: TypeError: 'type' object is not subscriptable
# when using the typing module in Python 3.8 or earlier.
from __future__ import annotations

import base64

import kmip.core.enums
import kmip.core.messages.payloads
import kmip.core.primitives
from kmip import enums
from kmip.pie import client

# Import exception for connection errors
from kmip.pie.exceptions import ClientConnectionFailure
from kmip.pie.objects import PublicKey

from tas.tas_logging import get_logger

# Setup logging for the KMIP plugin
logger = get_logger("tas.plugins.tas_kbm_kmip")


def kbm_open_client_connection(config_file=".pykmip/pykmip.conf"):
    """
    Opens a connection to the KMIP server using the PyKMIP ProxyKmipClient.

    Parameters:
        config_file (str): Path to the PyKMIP configuration file.

    Returns:
        ProxyKmipClient: An instance of the connected KMIP client.

    Raises:
        RuntimeError: If the connection to the KMIP server fails.
    """
    logger.info(f"Initializing KMIP client connection with config: {config_file}")
    try:
        # Initialize the KMIP client with the specified configuration file
        kmip_client = client.ProxyKmipClient(config_file=config_file)

        # Open the connection to the KMIP server
        logger.debug("Opening connection to KMIP server")
        kmip_client.open()
        logger.info("Successfully connected to the KMIP server.")

        return kmip_client

    except ClientConnectionFailure as e:
        logger.error(f"Failed to connect to KMIP server: {e}")
        raise RuntimeError(f"TAS-KBM: Failed to connect to the KMIP server: {e}")

    except Exception as e:
        logger.error(f"Unexpected error connecting to KMIP server: {e}")
        raise RuntimeError(
            f"TAS-KBM: An unexpected error occurred while connecting to the KMIP server: {e}"
        )


def kbm_close_client_connection(kmip_client):
    """
    Closes the connection to the KMIP server.

    Parameters:
        kmip_client (ProxyKmipClient): The KMIP client instance to close.

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


def _kbm_register_rsa_public_key(
    client,
    public_key_der: bytes,
    name: str = "Test TPM RSA Public Key",
) -> str:
    """
    Registers a transparent RSA public key with the KMIP server.

    This function creates a KMIP PublicKey object from the provided DER-encoded
    RSA public key bytes and registers it with the KMIP server using the given client.

    Parameters:
        client (ProxyKmipClient): The KMIP client instance used for registration.
        public_key_der (bytes): The DER-encoded RSA public key to register.
        name (str, optional): A descriptive name for the key in the KMIP server.
            Defaults to "Test TPM RSA Public Key".

    Returns:
        str: The unique identifier (UUID) assigned to the registered RSA public key.

    Raises:
        ValueError: If the registration process fails.
    """
    logger.info(f"Registering RSA public key with name: {name}")

    # Define the RSA public key attributes
    algorithm = enums.CryptographicAlgorithm.RSA
    length = 2048  # Key length in bits
    usage_mask = [
        enums.CryptographicUsageMask.ENCRYPT,
        enums.CryptographicUsageMask.WRAP_KEY,
    ]
    key_format_type = enums.KeyFormatType.PKCS_1

    logger.debug(f"Creating PublicKey object with algorithm={algorithm}")
    # Create a PublicKey object
    public_key = PublicKey(
        algorithm=algorithm,
        length=length,
        value=public_key_der,
        masks=usage_mask,
        format_type=key_format_type,
        name=name,
    )

    try:
        # Register the public key with the KMIP server
        logger.debug("Registering public key with KMIP server")
        key_id = client.register(public_key)
        if not key_id:
            logger.error("Failed to register RSA public key - no ID returned")
            raise ValueError("TAS-KBM: Failed to register RSA public key")
        else:
            logger.info(f"Successfully registered RSA public key with ID: {key_id}")

        # Activate the key
        logger.debug(f"Activating public key with ID: {key_id}")
        client.activate(key_id)
        logger.info(f"Successfully activated RSA public key with ID: {key_id}")
    except Exception as e:
        logger.error(f"Failed to register/activate RSA public key: {e}")
        raise ValueError(f"TAS-KBM: Failed to register RSA public key: {e}")
    return key_id


def _kbm_create_aes_encryption_key(
    client: client.ProxyKmipClient,
    name: str = "AES Encryption Key",
) -> str:
    """
    Creates and activates a 256-bit AES key using the KMIP protocol.

    Parameters:
        client (ProxyKmipClient): The KMIP client instance.
        name (str): A descriptive name for the new key.

    Returns:
        str: The unique identifier of the created AES key.
    """
    logger.info(f"Creating AES encryption key with name: {name}")

    # Define the AES key attributes
    algorithm = enums.CryptographicAlgorithm.AES
    length = 256
    usage_mask = [
        enums.CryptographicUsageMask.ENCRYPT,
        enums.CryptographicUsageMask.DECRYPT,
    ]

    logger.debug(f"Creating AES key with algorithm={algorithm}, length={length}")
    # Create a symmetric key
    try:
        aes_key = client.create(
            algorithm=algorithm,
            length=length,
            operation_policy_name="default",
            name=name,
            cryptographic_usage_mask=usage_mask,
        )
        logger.info(f"Successfully created AES encryption key with ID: {aes_key}")

        # Activate the key
        logger.debug(f"Activating AES key with ID: {aes_key}")
        client.activate(aes_key)
        logger.info(f"Successfully activated AES encryption key with ID: {aes_key}")
    except Exception as e:
        logger.error(f"Failed to create/activate AES encryption key: {e}")
        raise RuntimeError(
            f"TAS-KBM: Failed to create or activate AES encryption key: {e}"
        )

    return aes_key


def _kbm_encrypt_secrets_with_aes_cbc(
    client: client.ProxyKmipClient,
    key_id: str,
    secrets: bytes,
) -> tuple[bytes, bytes]:
    """
    Encrypts the given plaintext using AES in CBC mode.

    Parameters:
        client (ProxyKmipClient): The KMIP client used for encryption.
        key_id (str): The unique AES key identifier.
        secrets (bytes): The plaintext to encrypt.

    Returns:
        tuple[bytes, bytes]: A tuple containing:
            - The ciphertext as bytes.
            - The IV or extra data returned by the KMIP server.
    """
    logger.info(f"Encrypting secrets with AES-CBC using key ID: {key_id}")

    cryptographic_parameters = {
        "cryptographic_algorithm": enums.CryptographicAlgorithm.AES,
        "block_cipher_mode": enums.BlockCipherMode.CBC,
        "padding_method": enums.PaddingMethod.PKCS5,  # Only PKCS5 padding is supported
        "random_iv": True,
    }

    # Encrypt the plaintext using AES in CBC mode
    # The KMIP server will generate the IV for us
    try:
        ciphertext = client.encrypt(
            secrets,
            uid=key_id,
            cryptographic_parameters=cryptographic_parameters,
        )
        logger.info("Successfully encrypted secrets with AES-CBC")
    except Exception as e:
        logger.error(f"Failed to encrypt secrets: {e}")
        raise RuntimeError(f"TAS-KBM: Failed to encrypt the secrets: {e}")

    return ciphertext[0], ciphertext[1]


def kbm_wrap_aes_key_with_rsa_key(
    client: client.ProxyKmipClient,
    aes_key_id: str,
    rsa_key_id: str,
) -> bytes:
    """
    Wraps an AES key with an RSA public key using ProxyKmipClient.

    This is a different implementation from the one above.
    It gets the AES key in plaintext and then encrypts it with the RSA public key.
    """
    logger.info(f"Wrapping AES key {aes_key_id} with RSA key {rsa_key_id}")

    # Wrap the AES key with the RSA public key
    logger.debug(f"Retrieving AES key for wrapping: {aes_key_id}")
    secrets_key = client.get(
        aes_key_id,
    )

    # Encrypt the AES key with the RSA public key
    logger.debug("Encrypting AES key with RSA public key using OAEP padding")
    wrapped_key = client.encrypt(
        data=secrets_key.value,
        uid=rsa_key_id,
        cryptographic_parameters={
            "cryptographic_algorithm": enums.CryptographicAlgorithm.RSA,
            "padding_method": enums.PaddingMethod.OAEP,
            "hashing_algorithm": enums.HashingAlgorithm.SHA_256,
        },
    )
    logger.info("Successfully wrapped AES key with RSA public key")
    return wrapped_key[0]


def _kbm_retrieve_secrets(
    client: client.ProxyKmipClient,
    key_id: str,
) -> bytes:
    """
    Retrieves the secret associated with the given key_id from the KMIP server.
    Parameters:
        client (ProxyKmipClient): The KMIP client instance.
        key_id (str): The unique identifier of the secret to retrieve.
    Returns:
        bytes: The secret value as bytes.
    Raises:
        ValueError: If the retrieval process fails.
    """
    logger.info(f"Retrieving secret for key ID: {key_id}")
    try:
        # Retrieve the secret from the KMIP server
        logger.debug(f"Requesting secret from KMIP server for key: {key_id}")
        secret = client.get(key_id)
        if not secret:
            logger.error(f"No secret found for key ID: {key_id}")
            raise ValueError(f"TAS-KBM: No secret found for Key ID: {key_id}")

    except Exception as e:
        logger.error(f"Error retrieving secret for key ID {key_id}: {e}")
        raise ValueError(
            f"TAS-KBM: An error occurred while retrieving the secret for Key ID {key_id}: {e}"
        )

    logger.info(f"TAS-KBM: Retrieved secret for Key ID {key_id}")
    return secret.value


def _kbm_destroy_key(
    client: client.ProxyKmipClient,
    key_id: str,
) -> None:
    """
    Destroys the key associated with the given key_id on the KMIP server.
    Parameters:
        client (ProxyKmipClient): The KMIP client instance.
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
        client.revoke(enums.RevocationReasonCode.CESSATION_OF_OPERATION, key_id)
        logger.debug(f"Successfully revoked key with ID: {key_id}")

        # Destroy the key on the KMIP server
        logger.debug(f"Destroying key {key_id}")
        client.destroy(key_id)
        logger.info(f"Successfully destroyed key with ID: {key_id}")
    except Exception as e:
        logger.error(f"Error destroying key {key_id}: {e}")
        raise ValueError(
            f"TAS-KBM: An error occurred while destroying the key with ID {key_id}: {e}"
        )


def _kbm_wrap_secrets(
    client: client.ProxyKmipClient,
    secret_key_id: str,
    rsa_pub_key: bytes,
) -> tuple[bytes, bytes, bytes]:
    """
    Wraps a secret using the KMIP server.

    Parameters:
        client (ProxyKmipClient): The KMIP client instance.
        key_id (str): The id of the secret to be wrapped.
        secret (bytes): The secret to be wrapped.

    Returns:
        bytes: The wrapped key as bytes.
        bytes: The encrypted secret blob.
        bytes: The IV used for the encrypted secret blob.

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
        aes_key_id = _kbm_create_aes_encryption_key(client)
        logger.info(f"Created AES encryption key with ID: {aes_key_id}")

        # get the secret to be encrypted
        secrets = _kbm_retrieve_secrets(client, secret_key_id)
        logger.info(f"Retrieved secret for Key ID: {secret_key_id}")

        # Encrypt the secret using the AES key
        logger.debug("Encrypting secret with AES-CBC")
        ciphertext, iv = _kbm_encrypt_secrets_with_aes_cbc(
            client,
            aes_key_id,
            secrets,
        )
        logger.info(f"Encrypted secret with AES key ID: {aes_key_id}")

        # Register client's RSA public key with the KMIP server
        logger.debug("Registering client's RSA public key")
        rsa_key_id = _kbm_register_rsa_public_key(
            client,
            rsa_pub_key,
            name="Client's RSA Public Key",
        )
        logger.info(f"Registered RSA public key with ID: {rsa_key_id}")

        # Wrap the AES key with the RSA public key
        logger.debug("Wrapping AES key with RSA public key")
        wrapped_key = kbm_wrap_aes_key_with_rsa_key(
            client,
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
    return wrapped_key, ciphertext, iv


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


def _kbm_encode_secret(wrapped_key: bytes, blob: bytes, iv: bytes) -> dict:
    """
    Encodes the wrapped key, blob, and iv as a string.

    Parameters:
        wrapped_key (bytes): The wrapped key.
        blob (bytes): The encrypted secret blob.
        iv (bytes): The IV used for the encrypted secret blob.

    Returns:
        dict: The json representation of the wrapped key, blob, and iv.
    """

    # Create a dictionary with the wrapped key, blob, and iv
    data = {
        "wrapped_key": _kbm_encode_bytes_to_base64(wrapped_key),
        "blob": _kbm_encode_bytes_to_base64(blob),
        "iv": _kbm_encode_bytes_to_base64(iv),
    }

    return data


def kbm_get_secret(
    kmip_client: client.ProxyKmipClient, key_id: str, wrapping_key: bytes
) -> dict:
    """
    Retrieve the secret associated with the given key_id from the KMIP server.

    Parameters:
        key_id (str): The unique identifier of the secret to retrieve.
        wrapping_key (bytes): The wrapping key used to encrypt the secret.
        kmip_client (ProxyKmipClient): The KMIP client instance.

    Returns:
        dict: The secret as a jsonfiyable dictionary.

    Raises:
        ValueError: If the retrieval process fails.
        RuntimeError: If the KMIP server connection fails.
    """
    logger.info(f"KMIP get_secret request for key_id: {key_id}")

    try:
        wrapped_key, blob, iv = _kbm_wrap_secrets(
            kmip_client,
            key_id,
            wrapping_key,
        )
        if not wrapped_key or not blob or not iv:
            logger.error(f"Failed to retrieve/wrap secret for Key ID: {key_id}")
            raise ValueError(f"TAS-KBM: Failed to retrieve secret for Key ID: {key_id}")

        # Enocode secret payload as base64 string in a python dictionary
        logger.debug("Encoding wrapped secret as base64")
        secret = _kbm_encode_secret(
            wrapped_key,
            blob,
            iv,
        )
        if not secret:
            logger.error(f"Failed to encode secret for Key ID: {key_id}")
            raise ValueError(
                f"TAS-KBM: Failed to retrive and encode secret for Key ID: {key_id}"
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
