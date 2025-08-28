# GCP Confidential Space Signer

This document covers building and running the signer service on [Google Cloud Confidential Space](https://cloud.google.com/confidential-computing/confidential-space/docs), a confidential computing solution that allows you to process sensitive data in an isolated, attestable environment.

## Prerequisites

- Google Cloud SDK installed and configured
- Docker installed
- Access to Google Cloud Project with required APIs enabled:
  - Compute Engine API
  - Cloud KMS API
  - Artifact Registry API

## Building

Build the confidential signer Docker image:

```sh
docker build -f docker/confidential_signer.Dockerfile -t confidential-signer --build-arg RELEASE=1 .
```

Build args:

| Name        | Default | Description                                        |
| ----------- | ------- | -------------------------------------------------- |
| LISTEN_PORT | 2000    | TCP port for the signer service                    |
| RELEASE     |         | Set to non-empty to build optimized production version |

To build and push to Google Artifact Registry (update the registry path as needed):

```sh
# Build the Docker image and tag it for your Artifact Registry
docker build -f docker/confidential_signer.Dockerfile \
    -t <PATH_TO_ARTIFACT_REGISTRY_REPO>/confidential_signer_app .

# Push it to the registry
docker push <PATH_TO_ARTIFACT_REGISTRY_REPO>/confidential_signer_app
```

## Setup
Please refer to https://github.com/ecadlabs/signatory/blob/main/docs/confidential_space_setup.md
