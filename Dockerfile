# Build stage
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -ldflags "-s -w \
    -X main.version=$(git describe --tags --always --dirty 2>/dev/null || echo dev) \
    -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o xboard-node ./cmd/xboard-node

# Runtime stage — the mihomo kernel is a separate process, so its binary is
# fetched from the official release at image build time.
FROM alpine:3.20

ARG MIHOMO_VERSION=latest

RUN apk add --no-cache ca-certificates tzdata curl gzip \
    && mkdir -p /usr/local/bin \
    && TAG="$MIHOMO_VERSION" \
    && if [ "$TAG" = "latest" ]; then \
         TAG=$(curl -fsSL https://api.github.com/repos/MetaCubeX/mihomo/releases/latest \
               | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/'); \
       fi \
    && case "$(uname -m)" in \
         x86_64) SUFFIX="-compatible" ;; \
         *) SUFFIX="" ;; \
       esac \
    && curl -fsSL "https://github.com/MetaCubeX/mihomo/releases/download/${TAG}/mihomo-linux-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')${SUFFIX}-${TAG}.gz" \
       -o /tmp/mihomo.gz \
    && gunzip -f /tmp/mihomo.gz \
    && install -m 755 /tmp/mihomo /usr/local/bin/mihomo \
    && rm -f /tmp/mihomo \
    && /usr/local/bin/mihomo -v

COPY --from=builder /build/xboard-node /usr/local/bin/xboard-node

RUN mkdir -p /etc/xboard-node

WORKDIR /etc/xboard-node

# Config can be provided via file mount OR environment variables.
# Env var mode (no config file needed):
#   docker run -d --network=host \
#     -e apiHost=https://panel.example.com \
#     -e apiKey=YOUR_TOKEN \
#     -e nodeID=1 \
#     ghcr.io/guimc233/xboard-node:latest
#
# Supported env vars:
#   apiHost  / API_HOST    → panel URL
#   apiKey   / API_KEY     → server token
#   nodeID   / NODE_ID     → node ID
#   nodeType / NODE_TYPE   → node type (optional)
#   kernel   / KERNEL_TYPE → mihomo (only supported kernel)
#   domain   / DOMAIN      → TLS domain (enables auto_tls)
#   certFile / CERT_FILE   → TLS cert path
#   keyFile  / KEY_FILE    → TLS key path
#   logLevel / LOG_LEVEL   → log level

ENTRYPOINT ["xboard-node"]
CMD ["-c", "/etc/xboard-node/config.yml"]
