# Build stage
FROM golang:1.23-alpine AS builder
WORKDIR /build

# Copy the parent module (AI-Infra-Guard) since we reference it via replace directive
COPY go.mod go.sum ./
COPY cmd/ cmd/
COPY common/ common/
COPY internal/ internal/
COPY pkg/ pkg/

# Copy the sub-project
COPY ai-vuln-scanner/ ai-vuln-scanner/

# Build
WORKDIR /build/ai-vuln-scanner
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /ai-vuln-scanner .

# Runtime stage
FROM alpine:3.19
RUN apk --no-cache add ca-certificates tzdata
ENV TZ=Asia/Shanghai

WORKDIR /app
COPY --from=builder /ai-vuln-scanner /app/ai-vuln-scanner
COPY ai-vuln-scanner/data/fingerprints /app/data/fingerprints
COPY ai-vuln-scanner/data/vuln /app/data/vuln
COPY ai-vuln-scanner/data/vuln_en /app/data/vuln_en

ENV FP_DIR=/app/data/fingerprints
ENV VUL_DIR=/app/data/vuln
ENV VUL_DIR_EN=/app/data/vuln_en
ENV LISTEN_ADDR=:8899

EXPOSE 8899
ENTRYPOINT ["/app/ai-vuln-scanner"]
