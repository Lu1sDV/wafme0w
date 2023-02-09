FROM golang:1.19.5-alpine as build-env
RUN apk add build-base
RUN go install -v github.com/Lu1sDV/wafme0w/cmd/wafme0w@latest

FROM alpine:3.17.1
RUN apk add --no-cache bind-tools ca-certificates
COPY --from=build-env /go/bin/wafme0w /usr/local/bin/wafme0w
ENTRYPOINT ["wafme0w"]

