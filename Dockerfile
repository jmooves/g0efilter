FROM alpine:3.23.2

RUN apk add --no-cache nftables ca-certificates \
 && update-ca-certificates

WORKDIR /app

ARG TARGETPLATFORM

COPY ${TARGETPLATFORM}/g0efilter /app/g0efilter

ENTRYPOINT ["/app/g0efilter"]