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
  TOKEN=$(gcloud auth print-access-token)
  MGMT=apigee.googleapis.com

  {
    $CLI provision -o $ORG -e $ENV -t $TOKEN -r $RUNTIME -f -v > config.yaml
  } || { # exit directly if cli encounters any error
    exit 8
  }

  echo -e "\nCreating API Product httpbin-product..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}"\
    https://${MGMT}/v1/organizations/${ORG}/apiproducts \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d @${REPO}/kokoro/scripts/httpbin_product.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError creating API Product httpbin-product: $STATUS_CODE"
    exit 8
  fi  

  echo -e "\nCreating Application Developer integration@test.com..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/developers \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d @${REPO}/kokoro/scripts/developer.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError creating Application Developer integration@test.com: $STATUS_CODE"
    exit 8
  fi

  echo -e "\nCreating Application httpbin-app..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/developers/integration@test.com/apps \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d @${REPO}/kokoro/scripts/application.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError creating Application httpbin-app: $STATUS_CODE"
    exit 8
  fi

  echo -e "\nExtracting Application httpbin-app credentials..."
  APP=$(curl --silent \
    https://${MGMT}/v1/organizations/${ORG}/developers/integration@test.com/apps/httpbin-app \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json")
  {
    APIKEY=$(echo $APP | jq -r ".credentials[0].consumerKey")
    APISECRET=$(echo $APP | jq -r ".credentials[0].consumerSecret")
    echo -e "\nAPIKEY: $APIKEY"
    echo -e "\nAPISECRET: $APISECRET"
  } || {
    echo -e "\nError extracting credentials from Application httpbin-app: $STATUS_CODE"
    exit 8
  }
  if [[ -z $APIKEY ]] || [[ -z $APISECRET ]] ; then
    echo -e "\nError extracting credentials from Application httpbin-app: $STATUS_CODE"
    exit 8
  fi
}

################################################################################
# Undeploy remote-service API Proxies
################################################################################
function undeployRemoteServiceProxies {
  TOKEN=$(gcloud auth print-access-token)
  echo -e "\nGet deployed revision of API Proxies remote-service..."
  REV=$(docker run curlimages/curl:7.72.0 --silent \
    https://${MGMT}/v1/organizations/${ORG}/apis/remote-service/deployments \
    -H "Authorization: Bearer ${TOKEN}" | jq -r ".deployments[0].revision")
  echo -e "\nGot deployed revision $REV"

  if [[ ! -z $REV ]] ; then
    echo -e "\nUndeploying revision $REV of API Proxies remote-service..."
    STATUS_CODE=$(docker run curlimages/curl:7.72.0 -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
      https://${MGMT}/v1/organizations/${ORG}/environments/${ENV}/apis/remote-service/revisions/${REV}/deployments \
      -H "Authorization: Bearer ${TOKEN}")
    if [[ $STATUS_CODE -ge 299 ]] ; then
      echo -e "\nError undeploying API Proxies remote-service: $STATUS_CODE"
    fi
  fi

  for i in {1..20}
  do
    STATUS_CODE=$(curl --silent -o /dev/stderr -w "%{http_code}" \
     $RUNTIME/remote-service/version)
    if [[ $STATUS_CODE -ne 200 ]] ; then
      echo -e "\nUndeployed remote-service API Proxies"
      break
    fi
    sleep 10
  done
}

################################################################################
# Deploy remote-service API Proxies
################################################################################
function deployRemoteServiceProxies {
  if [[ ! -z $1 ]] ; then
    TOKEN=$(gcloud auth print-access-token)
    echo -e "\nDeploying revision $1 of API Proxies remote-service..."
    STATUS_CODE=$(docker run curlimages/curl:7.72.0 -X POST --silent -o /dev/stderr -w "%{http_code}" \
      https://${MGMT}/v1/organizations/${ORG}/environments/${ENV}/apis/remote-service/revisions/$1/deployments \
      -H "Authorization: Bearer ${TOKEN}")
    if [[ $STATUS_CODE -ge 299 ]] ; then
      echo -e "\nError undeploying API Proxies remote-service: $STATUS_CODE"
    fi
  fi

  for i in {1..20}
  do
    STATUS_CODE=$(curl --silent -o /dev/stderr -w "%{http_code}" \
     $RUNTIME/remote-service/version)
    if [[ $STATUS_CODE -eq 200 ]] ; then
      echo -e "\nDeployed remote-service API Proxies"
      break
    fi
    sleep 10
  done
}

################################################################################
# Apply configurations
################################################################################
function applyToCluster {
  echo -e "\nDeploying config.yaml and config files in ${1} to the cluster..."

  kubectl apply -f config.yaml

  kubectl annotate serviceaccount \                                                                                                                                     20:46:49   
    --namespace apigee \
    apigee-remote-service-envoy \
    iam.gke.io/gcp-service-account=apigee-udca@${PROJECT}.iam.gserviceaccount.com

  kubectl apply -f ${1}
}

################################################################################
# Clean up Apigee resources
################################################################################
function cleanUpApigee {
  echo -e "\nCleaning up resources applied to the Apigee Hybrid..."
  TOKEN=$(gcloud auth print-access-token)
  MGMT=apigee.googleapis.com

  echo -e "\nDeleting Application httpbin-app..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/developers/integration@test.com/apps/httpbin-app \
    -H "Authorization: Bearer ${TOKEN}")
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting Application httpbin-app: $STATUS_CODE"
  fi

  echo -e "\nDeleting Application Developer integration@test.com..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/developers/integration@test.com \
    -H "Authorization: Bearer ${TOKEN}")
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting Application Developer integration@test.com: $STATUS_CODE"
  fi

  echo -e "\nDeleting API Product httpbin-product..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/apiproducts/httpbin-product \
    -H "Authorization: Bearer ${TOKEN}")
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting API Product httpbin-product: $STATUS_CODE"
  fi

  echo -e "\nDeleting API Product remote-service..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/apiproducts/remote-service \
    -H "Authorization: Bearer ${TOKEN}")
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting API Product remote-service: $STATUS_CODE"
  fi

  undeployRemoteServiceProxies

  echo -e "\nDeleting API Proxies remote-service..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/apis/remote-service \
    -H "Authorization: Bearer ${TOKEN}")
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting API Proxies remote-service: $STATUS_CODE"
  fi

}

echo -e "\nStarting integration test of the Apigee Envoy Adapter with Apigee Hybrid..."

# load necessary function definitions
. ${KOKORO_ARTIFACTS_DIR}/github/apigee-remote-service-envoy/kokoro/scripts/lib.sh

setEnvironmentVariables hybrid-env

{
  cleanUpApigee
} || {
  echo -e "\n Apigee resources do not all exist."
}

buildDockerImages
provisionRemoteService

generateIstioSampleConfigurations istio-1.6

cleanUpKubernetes

applyToCluster istio-samples
runIstioTests

echo -e "\nFinished integration test of the Apigee Envoy Adapter with Apigee Hybrid."


