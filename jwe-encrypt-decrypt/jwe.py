import json

from jwcrypto import jwk, jwe


def encrypt(public_key: str, payload: dict) -> str:
    """Encrypts a payload using a given RSA public key in JWE format."""
    # Load the RSA public key from PEM-encoded string
    public_key_jwk = jwk.JWK.from_pem(public_key.encode('utf-8'))

    # Set the JWE protected header with encryption algorithms
    protected_header = {
        "alg": "RSA-OAEP-256",  # RSA-OAEP with SHA-256 for key encryption
        "enc": "A256GCM"  # AES-GCM with 256-bit key for content encryption
    }

    # Create the JWE object and encrypt the payload
    jwe_token = jwe.JWE(
        plaintext=json.dumps(payload).encode('utf-8'),
        recipient=public_key_jwk,
        protected=protected_header
    )

    # Serialize the encrypted JWE to compact serialization format
    return jwe_token.serialize(compact=True)


def decrypt(private_key: str, jwe_encrypted_payload: str) -> str:
    """Decrypts a JWE-encrypted payload using a given RSA private key."""
    # Load the RSA private key from PEM-encoded string
    private_key_jwk = jwk.JWK.from_pem(private_key.encode('utf-8'))

    # Deserialize the encrypted JWE and decrypt it
    jwe_token = jwe.JWE()
    jwe_token.deserialize(jwe_encrypted_payload, key=private_key_jwk)

    # Return the decrypted payload as a string
    return jwe_token.payload.decode('utf-8')
