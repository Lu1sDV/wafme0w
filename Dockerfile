FROM golang:1.27.3-alpine AS build
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/wafme0w ./cmd/wafme0w && mkdir -p /out/rootfs/tmp && chmod 1777 /out/rootfs/tmp

FROM scratch
COPY --from=build /out/rootfs/ /
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/wafme0w /usr/local/bin/wafme0w
COPY --from=build /src/LICENSE.md /LICENSE.md
ENTRYPOINT ["wafme0w"]
