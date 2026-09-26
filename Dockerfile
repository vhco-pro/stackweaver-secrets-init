FROM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS builder

WORKDIR /build

# No third-party dependencies by design: this is the one process in the release
# that holds secret-create RBAC, so it links the standard library only. There is
# no go.sum because there is nothing to verify.
COPY go.mod ./

COPY main.go .
COPY internal/ internal/

RUN CGO_ENABLED=0 GOOS=linux go build -o secrets-init .

# Runtime stage, distroless eliminates all OS-level CVEs
FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3

COPY --from=builder /build/secrets-init /secrets-init

ENTRYPOINT ["/secrets-init"]
