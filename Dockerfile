# Build stage
FROM golang:1.23-alpine AS builder
RUN apk --no-cache add git
WORKDIR /build

# Clone parent module (AI-Infra-Guard) which provides shared Go packages
ARG AIG_VERSION=v4.1.4
RUN git clone --depth 1 --branch ${AIG_VERSION} https://github.com/Tencent/AI-Infra-Guard.git

# Patch: raise redirect limit from 10 to 20 for sites with long redirect chains
COPY patches/ /tmp/patches/
RUN cd AI-Infra-Guard && git apply /tmp/patches/fix-redirect-limit.patch

# Copy the sub-project into the cloned repo tree so the replace directive works
COPY go.mod go.sum main.go AI-Infra-Guard/ai-vuln-scanner/
COPY static/ AI-Infra-Guard/ai-vuln-scanner/static/

# Build
WORKDIR /build/AI-Infra-Guard/ai-vuln-scanner
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /ai-vuln-scanner .

# Runtime stage
FROM alpine:3.19
RUN apk --no-cache add ca-certificates tzdata
ENV TZ=Asia/Shanghai

WORKDIR /app
COPY --from=builder /ai-vuln-scanner /app/ai-vuln-scanner
COPY data/fingerprints /app/data/fingerprints
COPY data/vuln /app/data/vuln
COPY data/vuln_en /app/data/vuln_en

ENV FP_DIR=/app/data/fingerprints
ENV VUL_DIR=/app/data/vuln
ENV VUL_DIR_EN=/app/data/vuln_en
ENV LISTEN_ADDR=:8899

EXPOSE 8899
ENTRYPOINT ["/app/ai-vuln-scanner"]
