FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod ./
COPY . .
RUN go mod tidy && go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/logixa-ingestor .
FROM alpine:3.20
RUN adduser -D -H appuser
USER appuser
COPY --from=builder /out/logixa-ingestor /logixa-ingestor
EXPOSE 8080
ENTRYPOINT ["/logixa-ingestor"]
