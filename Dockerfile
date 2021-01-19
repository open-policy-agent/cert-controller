FROM golang:1.14-alpine AS builder
WORKDIR /go/src/github.com/open-policy-agent/cert-controller

RUN apk add git

ENV CGO_ENABLED 0
COPY go.mod go.sum ./
RUN go mod download

COPY pkg pkg
COPY main.go ./
RUN go build -o cert-controller main.go


FROM scratch
WORKDIR /app

COPY --from=builder /go/src/github.com/open-policy-agent/cert-controller/cert-controller .
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

USER 1000:1000

CMD ["/app/cert-controller"]