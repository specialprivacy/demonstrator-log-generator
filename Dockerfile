FROM golang:alpine AS builder

WORKDIR /go/src/demonstrator-log-generator
COPY . .
RUN go mod init
RUN go build

FROM  alpine

ENV RATE=1s
CMD ["demonstrator-log-generator"]
RUN apk --update add ca-certificates

COPY --from=builder /go/src/demonstrator-log-generator /bin/
