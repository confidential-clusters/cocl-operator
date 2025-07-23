FROM quay.io/fedora/fedora:42

COPY target/debug/operator /usr/bin/operator

ENTRYPOINT ["/usr/bin/operator"]
