FROM docker.io/library/golang:1.27.4@sha256:5e8afd493a7124a8586e134d9b532731161d4b9becf9dee5a5956b107426f93d AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -o /frict-server ./cmd/frict-server

FROM scratch
# Roots for HTTPS to FCM.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /frict-server /frict-server
USER 65532:65532
ENTRYPOINT ["/frict-server"]
