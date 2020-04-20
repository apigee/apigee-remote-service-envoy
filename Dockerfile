# Keep in sync with Dockerfile_debug!

# Build binary in golang container #

FROM golang:1.14 as builder

RUN mkdir /app
ADD . /app/
WORKDIR /app

# Build service
# note: -ldflags '-s -w' strips debugger info
RUN CGO_ENABLED=0 go build -a -ldflags '-s -w' -o apigee-remote-service-envoy .

# Build runtime container #

FROM scratch

# Add certs
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Add service
COPY --from=builder /app/apigee-remote-service-envoy .

# Run
ENTRYPOINT ["/apigee-remote-service-envoy"]
EXPOSE 5000/tcp 5001/tcp
