# Signer RPC

All communication is done over [VSock](https://man7.org/linux/man-pages/man7/vsock.7.html) stream socket. Both request and reply consist of four bytes of an envelope length in big endian form followed by a [CBOR](https://cbor.io/) encoded message of that size. The length header was added to overcome limitations of some CBOR implementations which may have trouble reading from an endless stream.

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

This is the first request sent by the client. It's used to provide all information to initialize the encryption engine (KMS in this case).

```text
InitializeRequest = {
    Initialize: Credentials,
}

Credentials = {
    access_key_id: string,
    secret_access_key: string,
    session_token?: string,
    encryption_key_id: string,
    region: string,
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

A less secure way to get the private key into the enclave.

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
