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

# Default build arguments are set for the 'default' flavor (static, no cgo, no FIPS).
# These are overridden in the .github/workflows/docker.yaml for other flavors.

# Use golang:1.25-bookworm as the builder image.
ARG BUILD_CONTAINER=golang:1.25-bookworm@sha256:7af46e70d2017aef0b4ce2422afbcf39af0511a61993103e948b61011233ec42

ARG RUN_CONTAINER=gcr.io/distroless/static-debian12@sha256:cd64bec9cec257044ce3a8dd3620cf83b387920100332f2b041f19c4d2febf93

#--- Build binary in Go container ---#
FROM ${BUILD_CONTAINER} as builder

ARG CGO_ENABLED=0
ARG GODEBUG="fips140=on" 
ARG GOFIPS140=latest
ARG LDFLAGS="-s -w -X main.version=unknown -X main.commit=unknown -X main.date=unknown"
ARG GO_TAGS="netgo,osusergo" # Tags for static build

# Install git - required for go mod download in some base images.
USER root
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

# Build app
WORKDIR /app
ADD . .

RUN go mod download

# Build the application.
RUN echo "Building with: CGO_ENABLED=${CGO_ENABLED} GODEBUG=${GODEBUG} GOFIPS140=${GOFIPS140} GO_TAGS='${GO_TAGS}'"
RUN GOTOOLCHAIN=local GOOS=linux GOARCH=amd64 \
  CGO_ENABLED=${CGO_ENABLED} \
  GODEBUG=${GODEBUG} \
  GOFIPS140=${GOFIPS140} \
  go build -a \
  -tags="${GO_TAGS}" \
  -ldflags "${LDFLAGS}" \
  -o apigee-remote-service-envoy .

# add apigee:apigee user
RUN groupadd -g 999 apigee && \
    useradd -r -u 999 -g apigee apigee

# Adjust ca-certificates permissions if the file exists.
RUN if [ -f /etc/ssl/certs/ca-certificates.crt ]; then chmod a+r /etc/ssl/certs/ca-certificates.crt; fi

#--- Build runtime container ---#
FROM ${RUN_CONTAINER}

# Copy certs, app, and user
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENV GODEBUG=fips140=on
COPY --from=builder /app/apigee-remote-service-envoy /apigee-remote-service-envoy
COPY --from=builder /etc/passwd /etc/group /etc/shadow /etc/
USER apigee

EXPOSE 5000/tcp 5001/tcp

# Run entrypoint.
ENTRYPOINT ["/apigee-remote-service-envoy"]