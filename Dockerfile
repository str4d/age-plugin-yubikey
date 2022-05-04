# docker run --rm -it -v $(pwd):/src -v /run/pcscd/pcscd.comm:/run/pcscd/pcscd.comm rage-yubikey
FROM rust:alpine3.14 as base
RUN apk update \
    && apk add \
        git \
        gcc \
        g++ \
        pcsc-lite-dev \
        openssl \
        openssl-dev \
        pkgconfig

COPY . /src

WORKDIR /src
RUN RUSTFLAGS="-C target-feature=-crt-static" cargo build --release

RUN git clone --depth 1 https://github.com/str4d/rage.git \
    && cd rage \
    && cargo build --release

FROM alpine:3.14 as tool

RUN apk update \
    && apk add \
        libgcc \
        pcsc-lite-dev

COPY --from=base /src/target/release/age-plugin-yubikey /usr/local/bin/
COPY --from=base /src/rage/target/release/rage* /usr/local/bin/
WORKDIR /src
