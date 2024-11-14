import json

from jwe import encrypt, decrypt

# Default HTTP headers used in all responses
DEFAULT_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Origin, Content-Type, X-Auth-Token, Authorization",
    "Access-Control-Allow-Credentials": "true",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "0",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cache-Control": "must-revalidate"
}


def read_file(filepath: str) -> str:
    """Reads and returns the content of the file at the given filepath."""
    with open(filepath, "r", encoding="utf-8") as file:
        return file.read()


def success_response(data: dict) -> dict:
    """Returns a formatted success response dictionary."""
    return {
        "statusCode": 200,
        "headers": DEFAULT_HEADERS,
        "body": json.dumps(data)
    }


def error_response(message: str, status: int = 500) -> dict:
    """Returns a formatted error response dictionary with a specified status code."""
    return {
        "statusCode": status,
        "headers": DEFAULT_HEADERS,
        "body": json.dumps({"error": message})
    }


def process_encryption(path: str, request_body: dict, env: str, client_id: str) -> dict:
    """Handles the encryption process based on the provided API path."""
    if "/client/encrypt" in path and "payload" in request_body:
        # Encrypt client payload using Digitap public key
        payload = request_body.get("payload")
        public_key = read_file(f"./rsa_keys/{env}/digitap.pub")
        jwe_encrypted_payload = encrypt(public_key, payload)
        return success_response({"encrypted_client_payload": jwe_encrypted_payload})

    elif "/digitap/encrypt" in path and "response" in request_body:
        # Encrypt Digitap response using client's public key
        response = request_body.get("response")
        public_key = read_file(f"./rsa_keys/{env}/{client_id}.pub")
        jwe_encrypted_response = encrypt(public_key, response)
        return success_response({"encrypted_client_response": jwe_encrypted_response})


def process_decryption(path: str, request_body: dict, env: str, client_id: str) -> dict:
    """Handles the decryption process based on the provided API path."""
    if "/digitap/decrypt" in path and "payload" in request_body:
        # Decrypt Digitap payload using Digitap private key
        payload = request_body.get("payload")
        private_key = read_file(f"./rsa_keys/{env}/digitap.pem")
        jwe_decrypted_response = decrypt(private_key, payload)
        decrypted_payload = json.loads(jwe_decrypted_response)
        return success_response({"decrypted_client_payload": decrypted_payload})

    elif "/client/decrypt" in path and "response" in request_body:
        # Decrypt client response using client's private key
        response = request_body.get("response")
        private_key = read_file(f"./rsa_keys/{env}/{client_id}.pem")
        jwe_decrypted_response = decrypt(private_key, response)
        decrypted_response = json.loads(jwe_decrypted_response)
        return success_response({"decrypted_client_response": decrypted_response})


def main(event: dict, context: dict):
    """Main handler to process encryption or decryption requests based on the API path and keys."""
    try:
        # Parse the incoming event and extract relevant details
        request_body = json.loads(event.get("body", "{}"))
        path = event.get("path", "")
        client_id = request_body.get("client_id")
        env = request_body.get("env")

        # Print details for debugging
        print(f"Client ID: {client_id}, Environment: {env}")

        # Process encryption or decryption based on the request path
        if "/client/encrypt" in path or "/digitap/encrypt" in path:
            return process_encryption(path, request_body, env, client_id)

        elif "/digitap/decrypt" in path or "/client/decrypt" in path:
            return process_decryption(path, request_body, env, client_id)

        else:
            # Handle invalid paths
            print("Invalid path or operation.")
            return error_response("Invalid path or operation", status=400)

    except Exception as e:
        # Catch and handle any exceptions
        print(f"Error encountered: {e}")
        return error_response("Internal Server Error")
