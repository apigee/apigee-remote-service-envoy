# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Default build will be a standard Go binary in a distroless container.
# Default LDFLAGS includes `-s -w` to strip symbols for a small binary.

# Include the following LDFLAGS for version information in the binary:
# LDFLAGS="-X main.version=${BUILD_VERSION} -X main.commit=${BUILD_COMMIT} -X main.date=${BUILD_DATE}"

# Use the following combination to build an image linked with Boring Crypto:
# --build-arg CGO_ENABLED=1
# --build-arg BUILD_CONTAINER=goboring/golang:1.15.7b5
# --build-arg RUN_CONTAINER=gcr.io/distroless/base

ARG BUILD_CONTAINER=golang:1.15
ARG RUN_CONTAINER=gcr.io/distroless/static

#--- Build binary in Go container ---#
FROM ${BUILD_CONTAINER} as builder

ARG CGO_ENABLED=0
ARG LDFLAGS="-s -w -X main.version=unknown -X main.commit=unknown -X main.date=unknown" 

# Build app
WORKDIR /app
ADD . .
RUN go mod download
RUN CGO_ENABLED=$CGO_ENABLED go build -a \
  -ldflags "${LDFLAGS}" \
  -o apigee-remote-service-envoy .

# add apigee:apigee user
RUN groupadd -g 999 apigee && \
    useradd -r -u 999 -g apigee apigee

#--- Build runtime container ---#
FROM ${RUN_CONTAINER}

# Copy certs, app, and user
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /app/apigee-remote-service-envoy .
COPY --from=builder /etc/passwd /etc/group /etc/shadow /etc/
USER apigee

# Run entrypoint
ENTRYPOINT ["/apigee-remote-service-envoy"]
EXPOSE 5000/tcp 5001/tcp
