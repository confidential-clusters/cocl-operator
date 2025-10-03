# SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
# SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

ARG build_type
# Dependency build stage
FROM ghcr.io/confidential-clusters/buildroot AS builder
ARG build_type
WORKDIR /cocl-operator

COPY Cargo.toml Cargo.lock .
COPY crds crds
COPY rv-store rv-store
COPY operator/Cargo.toml operator/
COPY operator/src/lib.rs operator/src/

# Set only required crates as members to minimize rebuilds upon changes.
# Build dependencies in lower layer to make use of caching.
RUN sed -i 's/members = .*/members = ["crds", "operator", "rv-store"]/' Cargo.toml && \
    cargo build -p operator --lib $(if [ "$build_type" = release ]; then echo --release; fi)

# Target build stage
COPY operator/src operator/src
RUN cargo build -p operator $(if [ "$build_type" = release ]; then echo --release; fi)

# Distribution stage
FROM quay.io/fedora/fedora:42
ARG build_type
COPY --from=builder "/cocl-operator/target/$build_type/operator" /usr/bin
