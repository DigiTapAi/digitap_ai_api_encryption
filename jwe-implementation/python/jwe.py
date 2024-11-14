import json
import requests

from jwcrypto import jwk, jwe

def jwe_encrypt(public_key_pem, payload):
    """
    Encrypts the given payload using the provided public key in PEM format.

    :param public_key_pem: Public key in PEM format (string).
    :param payload: Payload to be encrypted (dict).
    :return: Encrypted JWE token (string).
    """
    # Load the public key
    public_key = jwk.JWK.from_pem(public_key_pem.encode('utf-8'))

    # Define the JWE header
    protected_header = {
        "alg": "RSA-OAEP-256",
        "enc": "A256GCM"
    }

    # Encrypt the payload
    jwetoken = jwe.JWE(json.dumps(payload).encode('utf-8'), recipient=public_key, protected=protected_header)
    encrypted_jwe = jwetoken.serialize(compact=True)

    return encrypted_jwe

def jwe_decrypt(private_key_pem, jwe_encrypted_payload):
    """
    Decrypts the provided JWE token using the private key in PEM format.

    :param private_key_pem: Private key in PEM format (string).
    :param jwe_encrypted_payload: Encrypted JWE token (string).
    :return: Decrypted payload (string).
    """
    # Load the private key
    private_key = jwk.JWK.from_pem(private_key_pem.encode('utf-8'))

    # Decrypt the JWE token
    jwetoken = jwe.JWE()
    jwetoken.deserialize(jwe_encrypted_payload, key=private_key)
    decrypted_payload = jwetoken.payload

    return decrypted_payload

if __name__ == "__main__":
    # Sample payload to encrypt
    request_payload = {
        "pan": "",
        "client_ref_num": "jwe-encryption-test"
    }

    # Public and Private key paths
    with open('public_key.pem', 'r') as pub_file:
        public_key_pem = pub_file.read()

    with open('private_key.pem', 'r') as priv_file:
        private_key_pem = priv_file.read()

    # Encrypt the payload
    encrypted_jwe = jwe_encrypt(public_key_pem, request_payload)
    print(f"Encrypted JWE: {encrypted_jwe}")

    # Generate Encrypted request payload
    encrypted_request_payload = {
        "encrypted_data": encrypted_jwe
    }

    headers = {
        'Authorization': 'Basic <Auth_Token>',
        'Content-Type': 'application/json',
    }

    response = requests.post(API_ENDPOINT, headers=headers, data=encrypted_request_payload)

    # Decrypt the payload
    decrypted_payload = jwe_decrypt(private_key_pem, response.json())
    print(f"Decrypted Payload: {decrypted_payload.decode('utf-8')}")