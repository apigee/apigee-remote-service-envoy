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

#!/bin/bash

################################################################################
# Build CLI from source code
################################################################################
function buildRemoteServiceCLI {
  echo -e "\nBuilding apigee-remote-service-cli..."
  cd ${REPOS_DIR}/apigee-remote-service-cli
  go mod download
  CGO_ENABLED=0 go build -a -o apigee-remote-service-cli .
  export CLI=${REPOS_DIR}/apigee-remote-service-cli/apigee-remote-service-cli
  cd -
}

################################################################################
# Build Adapter Docker Image from source code
################################################################################
function buildAdapterDocker {
  echo -e "\nBuilding local Docker image of apigee-remote-service-envoy..."
  cd ${REPOS_DIR}/apigee-remote-service-envoy
  docker build -t apigee-envoy-adapter:${ADAPTER_IMAGE_TAG} \
    --build-arg CGO_ENABLED=${GCO_ENABLED} \
    --build-arg RUN_CONTAINER=${RUN_CONTAINER} \
    --build-arg BUILD_CONTAINER=${BUILD_CONTAINER} \
    .
  cd -
}

################################################################################
# Build Target Docker Image from source code
################################################################################
function buildTargetDocker {
  cd ${REPOS_DIR}/apigee-remote-service-envoy/loadtest/target
  docker build -t apigee-target:test .
  cd -
}

################################################################################
# Fetching environment variables from secrets in the GCP project
################################################################################
function setEnvironmentVariables {
  echo -e "\nSetting up environment variables from the GCP secret ${1}..."
  gcloud secrets versions access 1 --secret="${1}" > ${1}
  source ./${1}
  REPO=${REPOS_DIR}/apigee-remote-service-envoy

  echo -e "\nGetting Kubernetes cluster credentials and configuring kubectl..."
  gcloud container clusters get-credentials $CLUSTER --zone $ZONE --project $PROJECT
}

################################################################################
# Pushing Docker images based on the latest source code
################################################################################
function pushDockerImages {
  echo -e "\nTagging and pushing the Docker image to gcr.io..."
  gcloud auth configure-docker gcr.io
  docker tag apigee-envoy-adapter:${1} gcr.io/${PROJECT}/apigee-envoy-adapter:${1}
  docker push gcr.io/${PROJECT}/apigee-envoy-adapter:${1}
  echo -e "\nDocker image pushed successfully."
}