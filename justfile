set shell := ["bash", "-uc"]

nitro_image := env_var_or_default("NITRO_IMAGE", "tee-signer-nitro")
confidential_space_image := env_var_or_default("CONFIDENTIAL_SPACE_IMAGE", "tee-signer-confidential-space")
image_tag := env_var_or_default("IMAGE_TAG", "dev")
eif_output := env_var_or_default("EIF_OUTPUT", "dist/nitro-signer.eif")

default:
    @just --list

fmt:
    cargo fmt --check

clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
    cargo test --workspace --all-features

build:
    cargo build --workspace --all-targets --all-features

build-release:
    cargo build --release --bin nitro_signer_app --bin confidential_signer_app

check: fmt clippy test build-release

image-nitro:
    docker build \
        -f docker/nitro_signer.Dockerfile \
        --build-arg RELEASE=1 \
        -t "{{ nitro_image }}:{{ image_tag }}" \
        .

image-confidential-space:
    docker build \
        -f docker/confidential_signer.Dockerfile \
        --build-arg RELEASE=1 \
        -t "{{ confidential_space_image }}:{{ image_tag }}" \
        .

images: image-nitro image-confidential-space

eif-nitro: image-nitro
    command -v nitro-cli >/dev/null || { echo "nitro-cli is required to build a Nitro EIF" >&2; exit 1; }
    mkdir -p "$(dirname "{{ eif_output }}")"
    nitro-cli build-enclave \
        --docker-uri "{{ nitro_image }}:{{ image_tag }}" \
        --output-file "{{ eif_output }}"
