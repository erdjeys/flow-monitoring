FROM golang:1.21-alpine AS builder
RUN apk add --no-cache libpcap-dev gcc musl-dev
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o agent .

FROM alpine:3.18
RUN apk add --no-cache libpcap
COPY --from=builder /app/agent /agent
ENTRYPOINT ["/agent"]
