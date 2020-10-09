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

# Fail on any error.
set -e

################################################################################
# Fetching environment variables from secrets in the GCP project
################################################################################
function setEnvironmentVariables {
  echo "Setting up environment variables from the GCP secret..."
  # temporary
  CLI=$HOME/repos/apigee-remote-service-cli/dist/default_linux_amd64/apigee-remote-service-cli
}

################################################################################
# Building Docker images based on the latest source code
################################################################################
function buildDockerImages {
  echo "Building the Docker image to gcr.io..."
  #gcloud builds submit -t gcr.io/envoyadapter-prod-func/apigee-envoy-adapter:test ${KOKORO_ARTIFACTS_DIR}/github/apigee-remote-service-envoy
  echo "Docker image built successfully."
}

################################################################################
# Provisioning remote-service
################################################################################
function provisionRemoteService {
  echo "Provisioning via CLI..."
  TOKEN=$(gcloud auth print-access-token)

  {
    $CLI provision -o $ORG -e $ENV -t $TOKEN -r $RUNTIME -f -v > config.yaml
  } || { # clean up and exit directly if cli encounters any error
    cleanUp
    exit 1
  }

  echo "Creating API Product httpbin-product..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}"\
    https://apigee.googleapis.com/v1/organizations/${ORG}/apiproducts \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d @httpbin_product.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo "Error creating API Product httpbin-product: $STATUS_CODE"
    cleanUp
    exit 1
  fi  

  echo "Creating Application Developer integration@test.com..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}" \
    https://apigee.googleapis.com/v1/organizations/${ORG}/developers \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d @developer.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo "Error creating Application Developer integration@test.com: $STATUS_CODE"
    cleanUp
    exit 1
  fi

  echo "Creating Application httpbin-app..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}" \
    https://apigee.googleapis.com/v1/organizations/${ORG}/developers/integration@test.com/apps \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d @application.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo "Error creating Application httpbin-app: $STATUS_CODE"
    cleanUp
    exit 1
  fi
}

################################################################################
# Generating sample configurations
################################################################################
function generateSampleConfigurations {
  echo "Generating sample configurations files for $1 via the CLI..."

  {
    $CLI samples create -c config.yaml --out samples --template $1
  } || { # clean up and exit directly if cli encounters any error
    cleanUp
    exit 1
  }
}

################################################################################
# Apply configurations
################################################################################
function applyToCluster {
  echo "Deploying config files to the cluster..."
}

################################################################################
# Run actual tests
################################################################################
function runTests {
  echo "Starting to run tests..."
}

################################################################################
# Clean up
################################################################################
function cleanUp {
  echo "Cleaning up resources applied to the Hybrid cluster..."
  TOKEN=$(gcloud auth print-access-token)

  echo "Deleting Application httpbin-app..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://apigee.googleapis.com/v1/organizations/${ORG}/developers/integration@test.com/apps/httpbin-app \
    -H "Authorization: Bearer ${TOKEN}")
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo "Error deleting Application httpbin-app: $STATUS_CODE"
  fi

  echo "Deleting Application Developer integration@test.com..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://apigee.googleapis.com/v1/organizations/${ORG}/developers/integration@test.com \
    -H "Authorization: Bearer ${TOKEN}")
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo "Error deleting Application Developer integration@test.com: $STATUS_CODE"
  fi

  echo "Deleting API Product httpbin-product..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://apigee.googleapis.com/v1/organizations/${ORG}/apiproducts/httpbin-product \
    -H "Authorization: Bearer ${TOKEN}")
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo "Error deleting API Product httpbin-product: $STATUS_CODE"
  fi

  echo "Deleting API Product remote-service..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://apigee.googleapis.com/v1/organizations/${ORG}/apiproducts/remote-service \
    -H "Authorization: Bearer ${TOKEN}")
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo "Error deleting API Product remote-service: $STATUS_CODE"
  fi

  echo "Undeploying API Proxies remote-service..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://apigee.googleapis.com/v1/organizations/${ORG}/environments/${ENV}/apis/remote-service/revisions/1/deployments \
    -H "Authorization: Bearer ${TOKEN}")
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo "Error undeploying API Proxies remote-service: $STATUS_CODE"
  fi

  echo "Deleting API Proxies remote-service..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://apigee.googleapis.com/v1/organizations/${ORG}/apis/remote-service \
    -H "Authorization: Bearer ${TOKEN}")
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo "Error deleting API Proxies remote-service: $STATUS_CODE"
  fi

  echo "Deleting configuration files..."
  if [[ -f "config.yaml" ]]; then
    rm config.yaml
  fi
  if [[ -d "samples" ]]; then
    rm -r samples
  fi
}

echo "Starting integration test of the Apigee Envoy Adapter with Apigee Hybrid..."

setEnvironmentVariables
buildDockerImages
provisionRemoteService
generateSampleConfigurations istio-1.6
applyToCluster
runTests
cleanUp

echo "Finished integration test of the Apigee Envoy Adapter with Apigee Hybrid."


