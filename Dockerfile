# Pin the official multi-platform index, not only its linux/amd64 manifest.
FROM docker.io/library/golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS toolchain

FROM toolchain AS runtime-files
COPY LICENSE.md /out/LICENSE.md
RUN mkdir -p /out/rootfs/tmp /out/rootfs/work \
    && chown 65532:65532 /out/rootfs/tmp /out/rootfs/work \
    && chmod 0700 /out/rootfs/tmp \
    && chmod 0750 /out/rootfs/work \
    && chmod 0444 /out/LICENSE.md /etc/ssl/certs/ca-certificates.crt

FROM scratch AS runtime-base
COPY --from=runtime-files --chown=0:0 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=runtime-files --chown=0:0 /out/LICENSE.md /LICENSE.md
COPY --from=runtime-files /out/rootfs/ /
ENV HOME=/work TMPDIR=/tmp
USER 65532:65532
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/wafmeow"]

# Release jobs provide a minimal context containing only the already-tested
# native archive binary and its license. No recompilation changes its identity.
FROM toolchain AS release-binary
COPY wafmeow /out/wafmeow
RUN chmod 0555 /out/wafmeow

FROM runtime-base AS release
COPY --from=release-binary --chown=0:0 /out/wafmeow /usr/local/bin/wafmeow

FROM toolchain AS build
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOWORK=off
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd/wafmeow/ ./cmd/wafmeow/
COPY internal/ ./internal/
COPY pkg/ ./pkg/
RUN go build -trimpath -buildvcs=false -o /out/wafmeow ./cmd/wafmeow \
    && chmod 0555 /out/wafmeow

FROM runtime-base AS runtime
COPY --from=build --chown=0:0 /out/wafmeow /usr/local/bin/wafmeow
