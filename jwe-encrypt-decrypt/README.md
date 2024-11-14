# Encryption/Decryption API
This repository contains a Python-based API service that handles encryption and decryption of 
data using the **json Web Encryption (JWE)** standard. The API facilitates secure communication between a client and Digitap, where the payloads and responses are encrypted and decrypted using RSA public and private keys.

## Features
* **Encryption**: Encrypts payloads and responses based on the provided API path.
* **Decryption**: Decrypts payloads and responses using the appropriate private keys.
* **RSA Key Handling**: Public and private keys are read from the specified environment (env) and client-specific directories.

## Endpoints
### 1. /client/encrypt
* Method: POST
* Description: Encrypts the payload from the client using Digitap's public key.
* Request Body:
```json
{
  "payload": "<client_payload>",
  "env": "<environment>",
  "client_id": "<client_id>"
}
```
* Response:
```json
{
  "statusCode": 200,
  "headers": { ... },
  "body": {
    "encrypted_client_payload": "<encrypted_payload>"
  }
}

```

### 2. /digitap/encrypt
* Method: POST
* Description: Encrypts the response from Digitap using the client's public key.
* Request Body:
```json
{
  "response": "<digitap_response>",
  "env": "<environment>",
  "client_id": "<client_id>"
}
```
* Response:
```json
{
  "statusCode": 200,
  "headers": { ... },
  "body": {
    "encrypted_client_response": "<encrypted_response>"
  }
}
```
### 3. /digitap/decrypt
* Method: POST
* Description: Decrypts the payload from Digitap using Digitap's private key.
* Request Body:
```json
{
  "payload": "<digitap_encrypted_payload>",
  "env": "<environment>",
  "client_id": "<client_id>"
}
```
* Response:
```json

{
  "statusCode": 200,
  "headers": { ... },
  "body": {
    "decrypted_client_payload": "<decrypted_payload>"
  }
}
```
### 4. /client/decrypt
* Method: POST
* Description: Decrypts the response from the client using the client's private key.
* Request Body:
```json

{
  "response": "<client_encrypted_response>",
  "env": "<environment>",
  "client_id": "<client_id>"
}
```
* Response:
```json

{
  "statusCode": 200,
  "headers": { ... },
  "body": {
    "decrypted_client_response": "<decrypted_response>"
  }
}
```
## Key Files
* RSA Keys:
  * Public keys are stored in the `./rsa_keys/<env>/digitap.pub` and `./rsa_keys/<env>/<client_id>.pub`.
  * Private keys are stored in the `./rsa_keys/<env>/digitap.pem` and `./rsa_keys/<env>/<client_id>.pem`.
* Environment: The env parameter specifies which environment's keys are used (e.g., dev, prod).


## Example Request and Response
### Encrypting Client Payload
* Request:

```json

{
  "payload": "This is a sample payload",
  "env": "prod",
  "client_id": "client123"
}
```
* Response:

```json

{
  "statusCode": 200,
  "headers": { ... },
  "body": {
    "encrypted_client_payload": "<JWE_encrypted_payload>"
  }
}
```
### Decrypting Client Response
* Request:

```json

{
  "response": "<JWE_encrypted_response>",
  "env": "prod",
  "client_id": "client123"
}
```
* Response:

```json

{
  "statusCode": 200,
  "headers": { ... },
  "body": {
    "decrypted_client_response": "This is the decrypted response"
  }
}
```
## Error Handling
The API returns the following error response formats:

* Invalid Path/Operation:
```json

{
  "statusCode": 400,
  "headers": { ... },
  "body": {
    "error": "Invalid path or operation"
  }
}
```
* Internal Server Error:
```json

{
  "statusCode": 500,
  "headers": { ... },
  "body": {
    "error": "Internal Server Error"
  }
}
```

## Requirements
* Python 3.7+
* Dependencies:
  * `jwe` for encryption and decryption
  * `json` for JSON handling 

You can install dependencies using pip:

```bash
pip install jwe
```

## Security
Ensure that the private keys are securely stored and handled. Public keys are required for encryption, while private keys are needed for decryption. Never expose private keys in publicly accessible locations.

## License
This project is licensed under the MIT License. See LICENSE for more details.