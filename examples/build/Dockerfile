# Stage 1: Build
FROM dhi.io/golang:1-alpine3.23 AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /build/g0efilter ./cmd/g0efilter

# Stage 2: Runtime
FROM dhi.io/alpine-base:3.23-alpine3.23-dev

RUN apk add --no-cache nftables ca-certificates \
    && update-ca-certificates

WORKDIR /app

COPY --from=builder /build/g0efilter /app/g0efilter

ENTRYPOINT ["/app/g0efilter"]
