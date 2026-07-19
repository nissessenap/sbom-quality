# Multi-stage build. Final image is golang:alpine because cyclonedx-gomod shells
# out to `go build` at runtime — the toolchain must be present, not just the CLI.
# Bundles the 5 runtime tools (sbomqs stays CI-only). Versions are manual ARG
# pins; keep them in sync with .github/workflows/sbomqs-gate.yml.
ARG GO_VERSION=1.26
ARG TRIVY_VERSION=0.72.0

ARG CYCLONEDX_GOMOD_VERSION=v1.10.0
ARG SBOMASM_VERSION=v2.0.9
ARG PARLAY_VERSION=v0.11.0
ARG SBOM_UTILITY_VERSION=v0.19.2

FROM aquasec/trivy:${TRIVY_VERSION} AS trivy

FROM golang:${GO_VERSION}-alpine AS builder
ARG CYCLONEDX_GOMOD_VERSION
ARG SBOMASM_VERSION
ARG PARLAY_VERSION
ARG SBOM_UTILITY_VERSION
# TARGETARCH is set by buildx; GOARCH=$TARGETARCH keeps arm64 a build-arg away.
ARG TARGETARCH
ENV CGO_ENABLED=0 GOARCH=${TARGETARCH}

RUN go install "github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@${CYCLONEDX_GOMOD_VERSION}" \
 && go install "github.com/interlynk-io/sbomasm/v2@${SBOMASM_VERSION}" \
 && go install "github.com/snyk/parlay@${PARLAY_VERSION}" \
 && go install "github.com/CycloneDX/sbom-utility@${SBOM_UTILITY_VERSION}"

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /out/sbom-quality ./cmd/sbom-quality

FROM golang:${GO_VERSION}-alpine
# git: cyclonedx-gomod reads the module version from git. ca-certificates: trivy
# image pulls and parlay's ecosyste.ms calls need TLS roots.
RUN apk add --no-cache git ca-certificates \
 && git config --system --add safe.directory '*'
# safe.directory '*': the container runs as root but the user's --go-mod repo is a
# bind-mount owned by their host uid; without this git refuses it as "dubious
# ownership" and cyclonedx-gomod's VCS stamping fails.

COPY --from=builder /go/bin/cyclonedx-gomod /go/bin/sbomasm /go/bin/parlay /go/bin/sbom-utility /usr/local/bin/
COPY --from=builder /out/sbom-quality /usr/local/bin/sbom-quality
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy

ENTRYPOINT ["sbom-quality"]
