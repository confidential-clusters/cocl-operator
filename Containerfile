# SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
# SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

FROM quay.io/fedora/fedora:42

COPY target/debug/operator /usr/bin/operator

ENTRYPOINT ["/usr/bin/operator"]
