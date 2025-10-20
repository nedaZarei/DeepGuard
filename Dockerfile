FROM golang:1.21-alpine AS builder

RUN apk add --no-cache gcc musl-dev git

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

ENV CGO_ENABLED=1
RUN go build -o deepguard -ldflags="-s -w" ./cmd/deepguard

FROM alpine:latest

RUN apk add --no-cache ca-certificates

RUN addgroup -g 1000 deepguard && \
    adduser -D -u 1000 -G deepguard deepguard

WORKDIR /app

COPY --from=builder /app/deepguard /usr/local/bin/deepguard

RUN mkdir -p /app/.deepguard /app/reports && \
    chown -R deepguard:deepguard /app

USER deepguard

ENTRYPOINT ["deepguard"]
CMD ["--help"]
