import argparse
import base64
import datetime
import json

# Add the tas directory to the path so we can import from it
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from tas.policy_helper import sort_dict_recursively


def sign_policy_file(policy_file_path, private_key):
    """Sign a policy file and return the signature."""
    try:
        # Read the policy file
        with open(policy_file_path, "r") as f:
            policy_data = json.load(f)

        measurements = policy_data["validation_rules"]
        sorted_measurements = sort_dict_recursively(measurements)

        # Convert to JSON bytes for signing
        measurements_json = json.dumps(
            sorted_measurements, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

        # Create signature using PSS padding and SHA384 hash
        signature = private_key.sign(
            measurements_json,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA384()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA384(),
        )
        return signature
    except FileNotFoundError:
        print(f"Error: Policy file '{policy_file_path}' not found.")
        return None
    except Exception as e:
        print(f"Error signing policy file: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(description="Sign policy files with RSA keys")
    parser.add_argument("policy_file", help="Path to the policy file to sign")
    parser.add_argument(
        "-o", "--output", help="Output file for signature (default: policy_file.sig)"
    )
    parser.add_argument(
        "--cert",
        action="store_true",
        help="Generate a certificate instead of just a public key",
    )

    args = parser.parse_args()

    if not os.path.exists("./policy_key.pem"):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        # Write our key to disk for safe keeping
        with open("./policy_key.pem", "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.BestAvailableEncryption(
                        b"passphrase"
                    ),
                )
            )
        print("Generated new policy key: policy_key.pem")
    else:
        print("Policy key already exists: policy_key.pem")
        with open("./policy_key.pem", "rb") as f:
            key = serialization.load_pem_private_key(
                f.read(),
                password=b"passphrase",
            )

    # Generate public key or certificate based on argument
    if args.cert:
        # Certificate mode
        if not os.path.exists("./policy_cert.pem"):
            print("Policy certificate not found. Creating self-signed cert for demo.")
            subject = issuer = x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Texas"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HPE"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "TAS Demo"),
                ]
            )
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
                .not_valid_after(
                    # Certificate will be valid for 10 days
                    datetime.datetime.now(datetime.timezone.utc)
                    + datetime.timedelta(days=10)
                )
                .add_extension(
                    x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                    critical=False,
                    # Sign certificate with private key
                )
                .sign(key, hashes.SHA384())
            )
            # Write certificate out to disk.
            with open("./policy_cert.pem", "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            print("Generated new policy certificate: policy_cert.pem")
        else:
            print("Policy certificate already exists: policy_cert.pem")
    else:
        # Public key mode (default)
        if not os.path.exists("./policy_public_key.pem"):
            print("Policy public key not found. Creating public key.")
            public_key = key.public_key()
            # Write public key out to disk
            with open("./policy_public_key.pem", "wb") as f:
                f.write(
                    public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                )
            print("Generated new policy public key: policy_public_key.pem")
        else:
            print("Policy public key already exists: policy_public_key.pem")

    # Sign the policy file
    signature = sign_policy_file(args.policy_file, key)
    if signature is None:
        sys.exit(1)

    # Determine output filename
    if args.output:
        output_file = args.output
    else:
        output_file = args.policy_file + ".sig"

    # Write signature to file
    try:
        signature_data = base64.b64encode(signature).decode("ascii")

        # Create JSON element for the signature
        signature_json = {
            "signature": {
                "algorithm": "SHA384",
                "padding": "PSS",
                "value": signature_data,
                "signed_data": "validation_rules",
            }
        }

        # Pretty print the JSON signature
        signature_json_str = json.dumps(signature_json, indent=2)
        print("Generated signature JSON element:")
        print(signature_json_str)

        with open(output_file, "w") as f:
            f.write(signature_json_str)

        print(f"\nPolicy file '{args.policy_file}' signed successfully.")
        print(f"Signature JSON written to: {output_file}")
        print("You can add the 'signature' object to your policy file.")
    except Exception as e:
        print(f"Error writing signature: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
    sys.exit(0)
