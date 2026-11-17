# syntax=docker/dockerfile:1

FROM golang:1.23-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/tracescrub ./cmd/tracescrub

FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app
COPY --from=builder /out/tracescrub /usr/local/bin/tracescrub
COPY configs/config.example.yaml /etc/tracescrub/config.yaml
COPY configs/trust-policy.example.json /etc/tracescrub/trust-policy.json

EXPOSE 8443 9090

ENTRYPOINT ["/usr/local/bin/tracescrub"]
CMD ["serve", "--config", "/etc/tracescrub/config.yaml"]
