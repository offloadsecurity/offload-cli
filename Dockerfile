# syntax=docker/dockerfile:1
#
# ghcr.io/offloadsecurity/offload-cli: the offload CLI plus the four scanners it
# drives (gitleaks, syft, grype, trivy) at the versions pinned in scanners.env,
# each verified against its published checksums before use.
#
#   docker run --rm -v "$PWD:/src" ghcr.io/offloadsecurity/offload-cli scan /src
#
# Vulnerability databases are NOT baked in: grype and trivy download them on
# first run into /cache (mount a volume there to reuse them across runs).

ARG GO_IMAGE=golang:1.26.11-alpine@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab
ARG RUNTIME_IMAGE=alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

# ---- offload CLI (cross-compiled on the build platform, CGO off) ----------
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
COPY main.go ./
COPY internal ./internal
# Version without the leading "v", matching the goreleaser binaries.
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath \
      -ldflags "-s -w -X github.com/offloadsecurity/offload-cli/internal/cli.Version=${VERSION#v}" \
      -o /out/offload . \
 && mkdir -p /out/licenses/go && cp "$(go env GOROOT)/LICENSE" /out/licenses/go/LICENSE

# ---- pinned scanners, checksum-verified by install.sh ---------------------
FROM --platform=$BUILDPLATFORM ${RUNTIME_IMAGE} AS scanners
ARG TARGETARCH
RUN apk add --no-cache curl
COPY install.sh scanners.env /tmp/offload/
RUN sh /tmp/offload/install.sh --scanners-only \
      --scanners-env /tmp/offload/scanners.env \
      --os linux --arch "$TARGETARCH" \
      --bin-dir /out/bin --licenses-dir /out/licenses

# ---- non-root user + writable cache dirs (no RUN in the final stage, so
# multi-arch builds need no emulation) ---------------------------------------
FROM --platform=$BUILDPLATFORM ${RUNTIME_IMAGE} AS rootfs
RUN mkdir -p /out/etc /out/home/offload /out/cache/grype /out/cache/trivy \
 && cp /etc/passwd /etc/group /out/etc/ \
 && echo "offload:x:10001:10001:offload:/home/offload:/sbin/nologin" >> /out/etc/passwd \
 && echo "offload:x:10001:" >> /out/etc/group \
 && chown -R 10001:10001 /out/home/offload /out/cache \
 && chmod 0777 /out/cache /out/cache/grype /out/cache/trivy

# ---- runtime ---------------------------------------------------------------
FROM ${RUNTIME_IMAGE}
ARG VERSION=dev
LABEL org.opencontainers.image.title="offload-cli" \
      org.opencontainers.image.description="Scan a repo for secrets, vulnerable dependencies and IaC misconfigurations (gitleaks, syft, grype, trivy)." \
      org.opencontainers.image.source="https://github.com/offloadsecurity/offload-cli" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=rootfs /out/etc/passwd /out/etc/group /etc/
COPY --from=rootfs /out/home/offload /home/offload
COPY --from=rootfs /out/cache /cache
COPY --from=scanners /out/bin/ /usr/local/bin/
COPY --from=build /out/offload /usr/local/bin/offload
COPY --from=scanners /out/licenses/ /usr/share/licenses/
COPY --from=build /out/licenses/ /usr/share/licenses/
COPY LICENSE NOTICE /usr/share/licenses/offload-cli/
COPY scanners.env /usr/share/offload-cli/scanners.env

ENV HOME=/home/offload \
    GRYPE_DB_CACHE_DIR=/cache/grype \
    TRIVY_CACHE_DIR=/cache/trivy

USER 10001:10001
WORKDIR /src
ENTRYPOINT ["offload"]
CMD ["help"]
