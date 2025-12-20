# Stage 1: Build
FROM golang:1.25.5-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go build -o g0efilter cmd/g0efilter/main.go

# Stage 2: Runtime
FROM alpine:3

RUN apk add --no-cache nftables

WORKDIR /app

COPY --from=builder /build/g0efilter /app/g0efilter

RUN apk add --no-cache nftables ca-certificates \
 && update-ca-certificates \
 && rm -rf /sbin/apk /etc/apk /lib/apk /var/cache/apk \
 && find /bin /usr/bin -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true \
 && find /sbin /usr/sbin -mindepth 1 -maxdepth 1 -type f ! -name nft -delete || true
 
ENTRYPOINT ["/app/g0efilter"]
