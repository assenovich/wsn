# syntax=docker/dockerfile:1

FROM golang:1.22.2 AS build-stage

WORKDIR /server
COPY server/* /server

RUN cd /server                                         \
    && CGO_ENABLED=0 GOOS=linux go build -o ws-server

FROM golang:1.22.2-bullseye AS build-release-stage

WORKDIR /app
COPY --from=build-stage /server/ws-server /app/ws-server

ENV WSN_LISTEN=0.0.0.0:666
ENV WSN_SECRET=

ENTRYPOINT ["/app/ws-server"]
