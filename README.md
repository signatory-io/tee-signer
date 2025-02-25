# Enclave Signer

The repository contains building blocks for signer services fitting into the specific architectural pattern: an enclave with no persistent storage and a bidirectional serial link to the host machine for RPC calls. All sensitive information is getting encrypted before sending back to the host for storage. At the moment the only supported platform is [AWS Nitro Enclave](https://aws.amazon.com/ec2/nitro/nitro-enclaves/), a fortified container with no persistent storage and no connection to the outside world other than bidirectional hypervisor-local [VSock](https://man7.org/linux/man-pages/man7/vsock.7.html) link to its parent instance.

## Prerequisites

For prerequisites refer to [kmstool setup procedure](https://github.com/aws/aws-nitro-enclaves-sdk-c/blob/main/docs/kmstool.md#prerequisites---linux)

## Building

From the root of this repo run:

```sh
docker build -f docker/nitro_signer.Dockerfile -t nitro-signer --build-arg RELEASE=1 .
```

Build args:

| Name        | Default | Description                                                  |
| ----------- | ------- | ------------------------------------------------------------ |
| PROXY_PORT  | 8000    | VSock proxy listening port                                   |
| PROXY_CID   | 3       | Context ID of an instance running a VSock proxy. 3 is a parent instance |
| LISTEN_PORT | 2000    | Signer listening port                                        |
| RELEASE     |         | Set non empty to build an optimized production version       |

This builds a minimalistic image based on Docker's `scratch`  to fit into Nitro's strict memory requirements. The image contains almost nothing but the binary itself and a few runtime libraries.

Next, you will have to build the EIF (Enclave Image Format) which is the bootable enclave format:

```sh
nitro-cli build-enclave --docker-uri nitro-signer --output-file nitro-signer.eif
```

## Running in debug mode

To run the enclave and see its output:

```sh
nitro-cli run-enclave --eif-path nitro-signer.eif --memory 1024 --cpu-count 2 --debug-mode
ENCLAVE_ID=$(nitro-cli describe-enclaves | jq -r .[0].EnclaveID)
# Connect to the enclave's terminal
nitro-cli console --enclave-id $ENCLAVE_ID
```

To make calls to KMS the enclave needs a VSock proxy service running on a parent instance. One option is to rely on [vsock-proxy](https://github.com/aws/aws-nitro-enclaves-cli/blob/main/vsock_proxy/README.md) utility supplied with [nitro-cli](https://github.com/aws/aws-nitro-enclaves-cli). To do so in a separate terminal window run:

```sh
CMK_REGION=us-west-2 # the region where you created your AWS KMS CMK
vsock-proxy 8000 kms.$CMK_REGION.amazonaws.com 443
```

Also `vsock-proxy` proxy can be ran as a system service or alternatively one can rely on [Signatory](https://github.com/ecadlabs/signatory) `nitro` backend's built in proxy.

Additionally [Signatory](https://github.com/ecadlabs/signatory) `nitro` backend supplies `rpctool` utility useful for making RPC requests to the signer for debugging purposes which also provides the proxy functionality.

## RPC Protocol

See [ the document](doc/rpc.md)

