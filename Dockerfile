FROM alpine:latest
COPY tinfoil-cli /usr/bin/tinfoil-cli
ENTRYPOINT ["/usr/bin/tinfoil-cli"]
