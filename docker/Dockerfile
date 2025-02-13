ARG BASE_IMAGE=public.ecr.aws/amazonlinux/amazonlinux:2

FROM $BASE_IMAGE

RUN yum install -y \
    gcc \
    git \
    tar \
    make

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal

COPY . /enclave-signer
RUN source $HOME/.cargo/env && cd enclave-signer && cargo build --release --bin nitro_signer_app
RUN cp /enclave-signer/target/release/nitro_signer_app /nitro_signer_app

ARG REGION
ARG PROXY_PORT
ARG PROXY_CID
ARG LISTEN_PORT

ENV REGION=${REGION}
ENV PROXY_PORT=${PROXY_PORT}
ENV PROXY_CID=${PROXY_CID}
ENV LISTEN_PORT=${LISTEN_PORT}

CMD ["/nitro_signer_app"]
