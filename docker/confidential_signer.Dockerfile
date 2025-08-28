ARG BASE_IMAGE=rust:1.88-slim

FROM $BASE_IMAGE AS builder

ARG RELEASE

RUN apt update && apt install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . /enclave-signer
RUN cd enclave-signer && cargo build ${RELEASE:+--release} --bin confidential_signer_app

RUN mkdir -p /rootfs
WORKDIR /rootfs

RUN [ ! -z "$RELEASE" ] && TGT="release" || TGT="debug"; \
    BINS="/enclave-signer/target/$TGT/confidential_signer_app" && \
    for bin in $BINS; do \
    ldd "$bin" | grep -Eo "/.*lib.*/[^ ]+" | \
    while read path; do \
    mkdir -p "./$(dirname $path)"; \
    cp -fL "$path" "./$path"; \
    done \
    done && \
    for bin in $BINS; do cp "$bin" .; done

RUN find ./

FROM scratch

COPY --from=builder /rootfs /

ARG LISTEN_PORT=2000

EXPOSE ${LISTEN_PORT}

ENV LISTEN_PORT=${LISTEN_PORT}


CMD ["/confidential_signer_app"]