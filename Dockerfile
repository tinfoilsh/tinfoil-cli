FROM alpine:latest
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/tinfoil /usr/bin/tinfoil
ENTRYPOINT ["/usr/bin/tinfoil"]
