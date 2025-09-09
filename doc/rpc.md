# Signer RPC

Messages are sent as a length-prefixed [CBOR](https://cbor.io/) stream: four bytes of big‑endian length followed by a CBOR-encoded message of that size. This framing avoids issues with CBOR decoders on endless streams.

Transport:
- AWS Nitro Enclave: VSock stream socket
- Google Cloud Confidential Space: TCP socket

All binary data is encoded as CBOR byte strings (type 2). Objects are encoded as string-keyed maps.

The server has no global state, all connections are handled independently.

The description is given in an improvised DSL.

## Response format

```text
Response<Result> = {
    (Ok: Result) | (Err: Error),
}

Error = {
    message: string,
    source?: Error,
}
```

## RPC Calls

### Initialize

This is the first request sent by the client. It's used to provide all information to initialize the encryption engine (cloud KMS wrapping in this case).

```text
InitializeRequest = {
    Initialize: Credentials,
}

# Credentials are platform-specific
Credentials (AWS) = {
    access_key_id: string,
    secret_access_key: string,
    session_token?: string,
    encryption_key_id: string,
    region: string,
}

Credentials (GCP) = {
    wip_provider_path: string,
    encryption_key_path: string,
}

InitializeResult = null
```

### Import

Used to import the encrypted private key that is stored on the host side.

```text
ImportRequest = {
    Import: bytes,
}

PublicKey = {
    (Secp256k1 | NistP256 | Ed25519 | Bls): bytes,
}

ImportResult = {
    public_key: PublicKey,
    handle: unsigned,
}
```

The private key will be decrypted, stored in the session-local in-memory storage and the derived public key will be returned alongside with the storage index aka handle.

### ImportUnencrypted

A less secure way to get the private key into the TEE.

```text
ImportUnencryptedRequest = {
    ImportUnencrypted: PrivateKey,
}

PrivateKey = {
    (Secp256k1 | NistP256 | Ed25519 | Bls): bytes,
}

ImportUnencryptedResult = GenerateAndImportResult
```

### Generate

Used to generate a new private key without storing it.

```text
GenerateRequest = {
    Generate: KeyType,
}

KeyType = "Secp256k1" | "NistP256" | "Ed25519" | "Bls"

GenerateResult = {
    encrypted_private_key: bytes,
    public_key: PublicKey,
}
```

### GenerateAndImport

Generate a new private key and store it in the session-local in-memory storage.

```text
GenerateAndImportRequest = {
    GenerateAndImport: KeyType,
}

GenerateAndImportResult = {
    encrypted_private_key: bytes,
    public_key: PublicKey,
    handle: unsigned,
}
```

### Sign

Sign the message with the key stored under the specified index.

```text
SignRequest = {
    Sign: {
        handle: unsigned,
        message: bytes,
        version: SigningVersion,
    },
}

Signature = {
  (Secp256k1 | NistP256 | Ed25519 | Bls): bytes,
}

SignResult = Signature
```

### SignWith

Sign the message with the provided encrypted private key.

```text
SignWithRequest = {
    SignWith: {
        encrypted_private_key: bytes,
        message: bytes,
        version: SigningVersion,
    }
}

SignWithResult = Signature
```

### PublicKey

Return the public key corresponding to the key pair stored under the given index.

```text
PublicKeyRequest = {
    PublicKey: unsigned,
}

PublicKeyResult = PublicKey
```

### PublicKeyFrom

Derive and return the public key corresponding to the given encrypted private key.

```text
PublicKeyFromRequest = {
    PublicKeyFrom: bytes,
}

PublicKeyFromResult = PublicKey
```

### ProvePossession

Return a proof of possession for algorithms that support it (currently BLS).

```text
ProvePossessionRequest = {
    ProvePossession: unsigned,  # handle
}

ProvePossessionResult = ProofOfPossession
```

## Binary Formats

### ECDSA

* Public key:  33 byte compressed point
* Private key: 32 byte big endian scalar
* Signature: 64 byte r|s big endian

### Ed25519

* Public key: 32 byte
* Private key: 32 byte
* Signature: 64 byte

### BLS

* Public key: 48 byte compressed point
* Private key: 32 byte scalar
* Signature: 96 byte compressed

## Notes

• KMS role: Cloud KMS is used to encrypt/decrypt wrapped private keys. All signing operations occur inside the TEE.
