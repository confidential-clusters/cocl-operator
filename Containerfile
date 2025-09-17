ARG build_type
# Dependency build stage
FROM ghcr.io/confidential-clusters/buildroot AS builder
ARG build_type
WORKDIR /cocl-operator

COPY Cargo.toml Cargo.lock .
COPY crds crds
COPY rv-store rv-store
COPY operator/Cargo.toml operator/

# Set only required crates as members to minimise rebuilds upon changes
# For debug builds, build dependencies to avoid full rebuild
RUN sed -i 's/members = .*/members = ["crds", "operator", "rv-store"]/' Cargo.toml && \
    if [ "$build_type" = debug ]; then \
        mkdir operator/src && \
        echo "fn main() {}" > operator/src/main.rs && \
        cargo build -p operator && \
        rm -rf target/debug/.fingerprint/operator-*; \
    fi

# Target build stage
COPY operator/src operator/src
RUN cargo build -p operator $(if [ "$build_type" = release ]; then echo --release; fi)

# Distribution stage
FROM quay.io/fedora/fedora:42
ARG build_type
COPY --from=builder "/cocl-operator/target/$build_type/operator" /usr/bin
