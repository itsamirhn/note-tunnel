FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG BASE_URL=http://cnote.ir
RUN go build -trimpath -ldflags="-s -w -X main.baseURL=${BASE_URL}" -o /note-tunnel .

FROM alpine:3
RUN apk add --no-cache ca-certificates
COPY --from=build /note-tunnel /usr/local/bin/note-tunnel
ENTRYPOINT ["note-tunnel"]
