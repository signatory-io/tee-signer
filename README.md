# TEE Signer

TEE Signer provides a portable, enclave-native signing service for high-assurance key custody. It runs inside hardware-isolated TEEs, keeps private keys in memory only, performs all signing inside the enclave, and uses cloud KMS solely to wrap (encrypt/decrypt) keys at the boundary. It exposes a consistent CBOR-over-stream RPC and ships backends for AWS Nitro Enclaves and Google Cloud Confidential Space, designed to integrate with Signatory (Tezos) and Signatory‑EVM.

The repository supports two confidential computing platforms:

## Supported Platforms

### AWS Nitro Enclave
A fortified container with no persistent storage and no connection to the outside world other than a bidirectional hypervisor-local [VSock](https://man7.org/linux/man-pages/man7/vsock.7.html) link to its parent instance.

### Google Cloud Confidential Space
A confidential computing solution that provides hardware-isolated environments for processing sensitive data with attestable security guarantees.

## Architecture

Both signers follow the same architectural pattern:
- **Isolated execution**: No persistent storage within the TEE
- **Encrypted communication**: All sensitive data is encrypted before leaving the secure environment
- **KMS integration**: Uses cloud provider KMS to wrap private keys (encrypt/decrypt). All signing occurs inside the TEE.
- **RPC interface**: Provides a consistent RPC protocol for signing operations

## Transports

| Platform | RPC Transport | Default Listen Port | Notes |
| --- | --- | --- | --- |
| AWS Nitro Enclave | VSock (in-enclave listener) | 2000 | Signatory connects over VSock. KMS access from enclave is via a VSock proxy on the parent instance. |
| Google Cloud Confidential Space | TCP (container listener) | 2000 | Signatory connects over TCP within the Confidential Space environment. |

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

Both signers implement the same RPC protocol over a length-prefixed CBOR stream; only the underlying transport differs by platform (see Transports). See [the RPC documentation](doc/rpc.md) for details on the signing interface.

## Integrations

This project is designed for use with [Signatory](https://signatory.io/) for Tezos and Signatory‑EVM.

## Project Status and Support

Beta Status: Both Nitro Enclave and Google Confidential Space backends are considered beta features. While we encourage operators to test these features, please exercise caution and report any issues. For support and feedback, please contact frontdesk@ecadlabs.com. We operate under a mutual "pre-NDA" basis for such inquiries.

Developed and maintained by the team at ECAD Labs Inc. We can add support for additional enclave systems by request; please reach out.
