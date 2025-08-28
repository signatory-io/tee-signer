# Enclave Signer

This repository contains building blocks for signer services that operate within secure enclaves - isolated execution environments with no persistent storage and limited communication channels to the host machine. All sensitive information is encrypted before being sent back to the host for storage.

The repository supports two confidential computing platforms:

## Supported Platforms

### AWS Nitro Enclave
A fortified container with no persistent storage and no connection to the outside world other than a bidirectional hypervisor-local [VSock](https://man7.org/linux/man-pages/man7/vsock.7.html) link to its parent instance.

### Google Cloud Confidential Space
A confidential computing solution that provides hardware-isolated environments for processing sensitive data with attestable security guarantees.

## Architecture

Both signers follow the same architectural pattern:
- **Isolated execution**: No persistent storage within the enclave
- **Encrypted communication**: All sensitive data is encrypted before leaving the secure environment
- **KMS integration**: Uses cloud provider KMS for key management and cryptographic operations
- **RPC interface**: Provides a consistent RPC protocol for signing operations

## Getting Started

Choose the appropriate setup guide based on your target platform:

- **[AWS Nitro Enclave Setup](doc/nitro-signer.md)** - Complete setup guide for AWS Nitro Enclaves
- **[GCP Confidential Space Setup](doc/confidential-signer.md)** - Complete setup guide for Google Cloud Confidential Space

## Project Structure

```
├── doc/                           # Documentation
│   ├── nitro-signer.md           # AWS Nitro Enclave setup guide
│   ├── confidential-signer.md    # GCP Confidential Space setup guide
│   └── rpc.md                    # RPC protocol documentation
├── docker/                       # Docker build files
│   ├── nitro_signer.Dockerfile   # AWS Nitro build
│   └── confidential_signer.Dockerfile # GCP Confidential Space build
├── nitro_signer/                 # AWS Nitro signer core library
├── nitro_signer_app/             # AWS Nitro signer application
├── confidential_signer/          # GCP Confidential signer core library
├── confidential_signer_app/      # GCP Confidential signer application
├── signer_core/                  # Shared cryptographic and RPC components
└── vsock/                        # VSock communication utilities
```

## RPC Protocol

Both signers implement the same RPC protocol for consistency across platforms. See [the RPC documentation](doc/rpc.md) for details on the signing interface.
