FROM golang:1.18.1-alpine
WORKDIR /p4
RUN apk add --no-cache libpcap-dev libc-dev gcc tcpdump iproute2
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY network/ network/
COPY mitm.go .
