FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o switch .

FROM alpine:3.18
COPY --from=builder /app/switch /switch
ENTRYPOINT ["/switch"]
