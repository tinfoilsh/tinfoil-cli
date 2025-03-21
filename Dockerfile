FROM alpine:latest
COPY tinfoil /usr/bin/tinfoil
ENTRYPOINT ["/usr/bin/tinfoil"]
