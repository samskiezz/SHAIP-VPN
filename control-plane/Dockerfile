# Build context: ./control-plane
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /control-plane .

FROM gcr.io/distroless/static-debian12
COPY --from=build /control-plane /control-plane
EXPOSE 8080
ENTRYPOINT ["/control-plane"]
