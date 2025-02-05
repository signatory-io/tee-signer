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

ENV REGION=""
ENV KEY_ID=""

ARG PROXY_PORT=8000
ARG PROXY_CID=3
ARG LISTEN_PORT=2000

CMD ["/nitro_signer_app", \
    "--region", ${REGION}, \
    "--key-id", ${KEY_ID}, \
    "--proxy-port", ${PROXY_PORT}, \
    "--proxy-cid", ${PROXY_CID}, \
    "--listen-port", ${LISTEN_PORT}]
