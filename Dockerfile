FROM golang:1.27-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS builder

WORKDIR /build

# No third-party dependencies by design: this is the one process in the release
# that holds secret-create RBAC, so it links the standard library only. There is
# no go.sum because there is nothing to verify.
COPY go.mod ./

COPY main.go .
COPY internal/ internal/

RUN CGO_ENABLED=0 GOOS=linux go build -o secrets-init .

# Runtime stage, distroless eliminates all OS-level CVEs
FROM gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7

COPY --from=builder /build/secrets-init /secrets-init

ENTRYPOINT ["/secrets-init"]
