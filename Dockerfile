# Pin the official multi-platform index, not only its linux/amd64 manifest.
FROM docker.io/library/golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOWORK=off
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd/wafme0w/ ./cmd/wafme0w/
COPY internal/ ./internal/
COPY pkg/ ./pkg/
COPY LICENSE.md ./
RUN go build -trimpath -buildvcs=false -o /out/wafme0w ./cmd/wafme0w \
    && mkdir -p /out/rootfs/tmp /out/rootfs/work \
    && chown 65532:65532 /out/rootfs/tmp /out/rootfs/work \
    && chmod 0700 /out/rootfs/tmp \
    && chmod 0750 /out/rootfs/work \
    && chmod 0555 /out/wafme0w \
    && chmod 0444 /src/LICENSE.md /etc/ssl/certs/ca-certificates.crt

FROM scratch
COPY --from=build --chown=0:0 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=0:0 /out/wafme0w /usr/local/bin/wafme0w
COPY --from=build --chown=0:0 /src/LICENSE.md /LICENSE.md
COPY --from=build /out/rootfs/ /
ENV HOME=/work TMPDIR=/tmp
USER 65532:65532
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/wafme0w"]
