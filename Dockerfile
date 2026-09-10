# syntax=docker/dockerfile:1
# Multi-stage build: static binary, distroless-style runtime, non-root.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/cpprobe ./cmd/cpprobe

FROM alpine:3.22 AS runtime
RUN apk add --no-cache ca-certificates libcap \
 && addgroup -S probe && adduser -S -G probe -h /var/lib/cpprobe probe
COPY --from=build /out/cpprobe /usr/local/bin/cpprobe
# Default server config; deploy/docker-compose.yml bind-mounts its own copy
# over this path.
COPY deploy/probe.yaml /etc/cpprobe/probe.yaml
# Ports below 1024 (53, 80, 443, 853) need CAP_NET_BIND_SERVICE; the file
# capability lets the process bind them without running as root.
RUN setcap cap_net_bind_service=+ep /usr/local/bin/cpprobe \
 && mkdir -p /var/lib/cpprobe/data && chown -R probe:probe /var/lib/cpprobe
USER probe
WORKDIR /var/lib/cpprobe
VOLUME ["/var/lib/cpprobe/data"]
ENTRYPOINT ["cpprobe"]
CMD ["server", "--config", "/etc/cpprobe/probe.yaml"]
