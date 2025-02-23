ARG BASE_IMAGE=public.ecr.aws/amazonlinux/amazonlinux:2

FROM $BASE_IMAGE AS builder

ARG RELEASE

RUN yum install -y \
    gcc \
    git \
    tar \
    make

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal

COPY . /enclave-signer
RUN source $HOME/.cargo/env && cd enclave-signer && cargo build ${RELEASE:+--release} --bin nitro_signer_app

RUN mkdir -p /rootfs
WORKDIR /rootfs

RUN [ ! -z "$RELEASE" ] && TGT="release" || TGT="debug"; \
    BINS="/enclave-signer/target/$TGT/nitro_signer_app" && \
    for bin in $BINS; do \
    ldd "$bin" | grep -Eo "/.*lib.*/[^ ]+" | \
    while read path; do \
    mkdir -p "./$(dirname $path)"; \
    cp -fL "$path" "./$path"; \
    done \
    done && \
    for bin in $BINS; do cp "$bin" .; done

RUN mkdir -p ./etc/pki/tls/certs/ && cp -f /etc/pki/tls/certs/* ./etc/pki/tls/certs/
RUN find ./

FROM scratch

COPY --from=builder /rootfs /

ARG REGION=us-west-2
ARG PROXY_PORT
ARG PROXY_CID
ARG LISTEN_PORT

ENV REGION=${REGION}
ENV PROXY_PORT=${PROXY_PORT}
ENV PROXY_CID=${PROXY_CID}
ENV LISTEN_PORT=${LISTEN_PORT}

CMD ["/nitro_signer_app"]
