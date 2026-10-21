# Digest-pinned runtime (Alpine 3.24, post CVE-2026-111943 ca-certificates).
# Refresh the digest together with any toolchain or base-image bump.
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/tinfoil /usr/bin/tinfoil
ENTRYPOINT ["/usr/bin/tinfoil"]
