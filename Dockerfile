## Multi-stage build for dns-tun-lb

FROM golang:1.25 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dns-tun-lb .

RUN apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
	&& setcap cap_net_bind_service=+ep /app/dns-tun-lb \
	&& apt-get purge -y --auto-remove libcap2-bin \
	&& rm -rf /var/lib/apt/lists/*

FROM gcr.io/distroless/base-debian12

WORKDIR /

COPY --from=builder /app/dns-tun-lb /dns-tun-lb
COPY lb.example.yaml /etc/dns-tun-lb.yaml

USER nonroot:nonroot

ENTRYPOINT ["/dns-tun-lb", "-config", "/etc/dns-tun-lb.yaml"]

