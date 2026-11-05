FROM docker.io/library/golang:1.27.3 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -o /duo-stub ./cmd/duo-stub

FROM scratch
COPY --from=build /duo-stub /duo-stub
USER 65532:65532
ENTRYPOINT ["/duo-stub"]
