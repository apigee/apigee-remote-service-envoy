## Integration test scripts

### Exit code definition

1 - configuration generation error

2 - local target call error with API key

3 - local target call error with JWT

4 - K8s/Istio target call error with API key

5 - K8s/Istio target call error with JWT

6 - other errors during tests running on k8s/Istio

7 - other errors during tests running locally

8 - error provisioning with Hybrid

9 - error provisioning with CG SaaS

10 - error during load tests

### Run the test locally

*NOTE*: The test scripts serve the Kokoro builds internally. As of now they do not create a sandbox environment. Instead they rely on existing Apigee platforms and credentials. Therefore, running the scripts locally still require permission to access those resources and they are not meant for general use. However, some functions defined in `scripts/lib.sh` might appear to be useful.

Given proper access to the credentials, the script below can be used to simulate the Kokoro builds locally.

GCloud SDK command-line tool, Go 1.16+ and jq are required.

```bash
#!/bin/bash

# Fail on any error.
set -e

export REPOS_DIR=${path to your apigee-remote-service-envoy and apigee-remote-service-cli repos}
export BUILD_DIR=${REPOS_DIR}/apigee-remote-service-envoy/integration-test

export CGSAAS_ISTIO_TEMPLATE=istio-1.7
export CGSAAS_ENVOY_TEMPLATE=envoy-1.16
export CGSAAS_ENVOY_TAG=v1.16.0
export HYBRID_ISTIO_TEMPLATE=istio-1.6
export HYBRID_ENVOY_TEMPLATE=envoy-1.16
export HYBRID_ENVOY_TAG=v1.16.0
export OPDK_ENVOY_TEMPLATE=envoy-1.15
export OPDK_ENVOY_TAG=v1.15.0
export CGO_ENABLED=0 # 1
export RUN_CONTAINER=gcr.io/distroless/base # ubuntu:xenial
export BUILD_CONTAINER=golang:1.16 # goboring/golang:1.16.1b7

# uncomment one of the following command to test a specific Apigee platform
# export ADAPTER_IMAGE_TAG=hybrid-test
# export ADAPTER_IMAGE_TAG=opdk-test
# export ADAPTER_IMAGE_TAG=cgsaas-test

. ${BUILD_DIR}/scripts/init.sh

# uncomment one of the following command to test a specific Apigee platform
# ${BUILD_DIR}/scripts/hybrid_test.sh
# ${BUILD_DIR}/scripts/opdk_test.sh
# ${BUILD_DIR}/scripts/cgsaas_test.sh
```
