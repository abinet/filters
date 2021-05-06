FROM golang:1.13.5 as builder
RUN git clone https://github.com/zalando/skipper.git /skipper
RUN cd /skipper && make skipper
COPY . /skipper/plugins/filters/
RUN cd /skipper/plugins/filters && CGO_ENABLED=1 GO111MODULE=on go build -buildmode=plugin -o jwtvalidation.so ./jwtvalidation/jwtvalidation.go ./jwtvalidation/auth.go ./jwtvalidation/authclient.go
FROM ubuntu:latest
RUN mkdir -p /usr/bin
COPY --from=builder /skipper/bin/skipper /usr/bin/
COPY --from=builder /skipper/plugins/filters/*.so /plugins/
ENTRYPOINT ["/usr/bin/skipper"]
