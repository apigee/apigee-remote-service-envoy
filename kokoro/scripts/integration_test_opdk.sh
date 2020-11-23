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
# Provisioning remote-service
################################################################################
function provisionRemoteService {
  echo -e "\nProvisioning via CLI..."
  {
    $CLI provision -o $ORG -e $ENV -u $USER -p $PASSWORD --opdk \
      --management $MGMTURL --runtime $RUNTIME \
      --virtual-hosts default -f > config.yaml
    chmod 644 config.yaml
  } || { # exit directly if cli encounters any error
    exit 9
  }

  echo -e "\nCreating API Product httpbin-product..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}"\
    ${MGMTURL}/v1/organizations/${ORG}/apiproducts \
    -u $USER:$PASSWORD \
    -H "Content-Type: application/json" \
    -d @${REPO}/kokoro/scripts/httpbin_product.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError creating API Product httpbin-product: $STATUS_CODE"
    exit 9
  fi  

  echo -e "\nCreating Application Developer integration@test.com..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}" \
    ${MGMTURL}/v1/organizations/${ORG}/developers \
    -u $USER:$PASSWORD \
    -H "Content-Type: application/json" \
    -d @${REPO}/kokoro/scripts/developer.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError creating Application Developer integration@test.com: $STATUS_CODE"
    exit 9
  fi

  echo -e "\nCreating Application httpbin-app..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}" \
    ${MGMTURL}/v1/organizations/${ORG}/developers/integration@test.com/apps \
    -u $USER:$PASSWORD \
    -H "Content-Type: application/json" \
    -d @${REPO}/kokoro/scripts/application.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError creating Application httpbin-app: $STATUS_CODE"
    exit 9
  fi

  echo -e "\nExtracting Application httpbin-app credentials..."
  APP=$(curl --silent \
    ${MGMTURL}/v1/organizations/${ORG}/developers/integration@test.com/apps/httpbin-app \
    -u $USER:$PASSWORD \
    -H "Content-Type: application/json")
  {
    APIKEY=$(echo $APP | jq -r ".credentials[0].consumerKey")
    APISECRET=$(echo $APP | jq -r ".credentials[0].consumerSecret")
    echo -e "\nAPIKEY: $APIKEY"
    echo -e "\nAPISECRET: $APISECRET"
  } || {
    echo -e "\nError extracting credentials from Application httpbin-app: $STATUS_CODE"
    exit 9
  }
  if [[ -z $APIKEY ]] || [[ -z $APISECRET ]] ; then
    echo -e "\nError extracting credentials from Application httpbin-app: $STATUS_CODE"
    exit 9
  fi
}

################################################################################
# Deploy remote-service API Proxies
################################################################################
function deployRemoteServiceProxies {
  if [[ ! -z $1 ]] ; then
    TOKEN=$(gcloud auth print-access-token)
    echo -e "\nDeploying revision $1 of API Proxies remote-service..."
    STATUS_CODE=$(docker run curlimages/curl:7.72.0 -X POST --silent -o /dev/stderr -w "%{http_code}" \
      ${MGMTURL}/v1/organizations/${ORG}/environments/${ENV}/apis/remote-service/revisions/$1/deployments \
      -u $USER:$PASSWORD)
    if [[ $STATUS_CODE -ge 299 ]] ; then
      echo -e "\nError undeploying API Proxies remote-service: $STATUS_CODE"
    fi
  fi
}

################################################################################
# Undeploy remote-service API Proxies
################################################################################
function undeployRemoteServiceProxies {
  TOKEN=$(gcloud auth print-access-token)
  echo -e "\nGet deployed revision of API Proxies remote-service..."
  REV=$(docker run curlimages/curl:7.72.0 --silent \
    ${MGMTURL}/v1/organizations/${ORG}/apis/remote-service \
    -u $USER:$PASSWORD | jq -r ".revision | max")
  echo -e "\nGot deployed revision $REV"

  if [[ ! -z $REV ]] ; then
    echo -e "\nUndeploying revision $REV of API Proxies remote-service..."
    STATUS_CODE=$(docker run curlimages/curl:7.72.0 -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
      ${MGMTURL}/v1/organizations/${ORG}/environments/${ENV}/apis/remote-service/revisions/${REV}/deployments \
      -u $USER:$PASSWORD)
    if [[ $STATUS_CODE -ge 299 ]] ; then
      echo -e "\nError undeploying API Proxies remote-service: $STATUS_CODE"
    fi
  fi
}

################################################################################
# Clean up Apigee resources
################################################################################
function cleanUpApigee {
  echo -e "\nCleaning up resources applied to the Apigee OPDK..."

  echo -e "\nDeleting Application httpbin-app..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    ${MGMTURL}/v1/organizations/${ORG}/developers/integration@test.com/apps/httpbin-app \
    -u $USER:$PASSWORD)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting Application httpbin-app: $STATUS_CODE"
  fi

  echo -e "\nDeleting Application Developer integration@test.com..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    ${MGMTURL}/v1/organizations/${ORG}/developers/integration@test.com \
    -u $USER:$PASSWORD)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting Application Developer integration@test.com: $STATUS_CODE"
  fi

  echo -e "\nDeleting API Product httpbin-product..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    ${MGMTURL}/v1/organizations/${ORG}/apiproducts/httpbin-product \
    -u $USER:$PASSWORD)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting API Product httpbin-product: $STATUS_CODE"
  fi

  echo -e "\nDeleting API Product remote-service..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    ${MGMTURL}/v1/organizations/${ORG}/apiproducts/remote-service \
    -u $USER:$PASSWORD)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting API Product remote-service: $STATUS_CODE"
  fi

  undeployRemoteServiceProxies

  echo -e "\nDeleting API Proxies remote-service..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    ${MGMTURL}/v1/organizations/${ORG}/apis/remote-service \
    -u $USER:$PASSWORD)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting API Proxies remote-service: $STATUS_CODE"
  fi

}

echo -e "\nStarting integration test of the Apigee Envoy Adapter with Apigee OPDK..."

# load necessary function definitions
. ${KOKORO_ARTIFACTS_DIR}/github/apigee-remote-service-envoy/kokoro/scripts/lib.sh

setEnvironmentVariables opdk-env

{
  cleanUpApigee
  docker stop envoy
  docker stop adapter
} || {
  echo -e "\n Apigee resources do not all exist."
}

provisionRemoteService

generateEnvoySampleConfigurations envoy-1.15

runEnvoyTests v1.15.0

echo -e "\nFinished integration test of the Apigee Envoy Adapter with Apigee OPDK."