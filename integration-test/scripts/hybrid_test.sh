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
    $CLI provision -o $ORG -e $ENV -t $TOKEN -r $RUNTIME -f -v > config1.yaml
    $CLI provision -o $ORG -e $ENV2 -t $TOKEN -r $RUNTIME2 -v > config2.yaml
  } || { # exit directly if cli encounters any error
    exit 8
  }

  echo -e "\nCreating API Product httpbin-product..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/apiproducts \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d @${REPO}/integration-test/payloads/hybrid_product.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError creating API Product httpbin-product: $STATUS_CODE"
    exit 8
  fi

  echo -e "\nCreating API Product opgrp-product..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/apiproducts \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d @${REPO}/integration-test/payloads/opgrp_product.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError creating API Product opgrp-product: $STATUS_CODE"
    exit 8
  fi

  echo -e "\nCreating API Product dummy-product..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/apiproducts \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d @${REPO}/integration-test/payloads/dummy_product.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError creating API Product dummy-product: $STATUS_CODE"
    exit 8
  fi

  echo -e "\nCreating Application Developer integration@test.com..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/developers \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d @${REPO}/integration-test/payloads/developer.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError creating Application Developer integration@test.com: $STATUS_CODE"
    exit 8
  fi

  echo -e "\nCreating Application httpbin-app..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/developers/integration@test.com/apps \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d @${REPO}/integration-test/payloads/hybrid_app.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError creating Application httpbin-app: $STATUS_CODE"
    exit 8
  fi

  echo -e "\nCreating Application wrong-prod-app..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/developers/integration@test.com/apps \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d @${REPO}/integration-test/payloads/wrong-prod_app.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError creating Application wrong-prod-app: $STATUS_CODE"
    exit 8
  fi

  echo -e "\nCreating Application cred-exp-app..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/developers/integration@test.com/apps \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d @${REPO}/integration-test/payloads/cred-expired_app.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError creating Application cred-exp-app: $STATUS_CODE"
    exit 8
  fi

  echo -e "\nCreating Application unapproved-app..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/developers/integration@test.com/apps \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d @${REPO}/integration-test/payloads/unapproved_app.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError creating Application unapproved-app: $STATUS_CODE"
    exit 8
  fi

  echo -e "\nCreating Application prod-unapproved-app..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/developers/integration@test.com/apps \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d @${REPO}/integration-test/payloads/prod-unapproved_app.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError creating Application prod-unapproved-app: $STATUS_CODE"
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

  echo -e "\nExtracting Application wrong-prod-app credentials..."
  APP=$(curl --silent \
    https://${MGMT}/v1/organizations/${ORG}/developers/integration@test.com/apps/wrong-prod-app \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json")
  {
    WRONG_APIKEY=$(echo $APP | jq -r ".credentials[0].consumerKey")
    WRONG_APISECRET=$(echo $APP | jq -r ".credentials[0].consumerSecret")
    echo -e "\nWRONG_APIKEY: $WRONG_APIKEY"
    echo -e "\nWRONG_APISECRET: $WRONG_APISECRET"
  } || {
    echo -e "\nError extracting credentials from Application wrong-prod-app: $STATUS_CODE"
    exit 8
  }
  if [[ -z $WRONG_APIKEY ]] || [[ -z $WRONG_APISECRET ]] ; then
    echo -e "\nError extracting credentials from Application wrong-prod-app: $STATUS_CODE"
    exit 8
  fi

  echo -e "\nExtracting Application cred-exp-app credentials..."
  APP=$(curl --silent \
    https://${MGMT}/v1/organizations/${ORG}/developers/integration@test.com/apps/cred-exp-app \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json")
  {
    EXPIRED_APIKEY=$(echo $APP | jq -r ".credentials[0].consumerKey")
    EXPIRED_APISECRET=$(echo $APP | jq -r ".credentials[0].consumerSecret")
    echo -e "\nEXPIRED_APIKEY: $EXPIRED_APIKEY"
    echo -e "\nEXPIRED_APISECRET: $EXPIRED_APISECRET"
  } || {
    echo -e "\nError extracting credentials from Application cred-exp-app: $STATUS_CODE"
    exit 8
  }
  if [[ -z $EXPIRED_APIKEY ]] || [[ -z $EXPIRED_APISECRET ]] ; then
    echo -e "\nError extracting credentials from Application cred-exp-app: $STATUS_CODE"
    exit 8
  fi

  echo -e "\nExtracting Application unapproved-app credentials..."
  APP=$(curl --silent \
    https://${MGMT}/v1/organizations/${ORG}/developers/integration@test.com/apps/unapproved-app \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json")
  {
    REVOKED_APIKEY=$(echo $APP | jq -r ".credentials[0].consumerKey")
    REVOKED_APISECRET=$(echo $APP | jq -r ".credentials[0].consumerSecret")
    echo -e "\nREVOKED_APIKEY: $REVOKED_APIKEY"
    echo -e "\nREVOKED_APISECRET: $REVOKED_APISECRET"
  } || {
    echo -e "\nError extracting credentials from Application unapproved-app: $STATUS_CODE"
    exit 8
  }
  if [[ -z $REVOKED_APIKEY ]] || [[ -z $REVOKED_APISECRET ]] ; then
    echo -e "\nError extracting credentials from Application unapproved-app: $STATUS_CODE"
    exit 8
  fi

  echo -e "\nExtracting Application prod-unapproved-app credentials..."
  APP=$(curl --silent \
    https://${MGMT}/v1/organizations/${ORG}/developers/integration@test.com/apps/prod-unapproved-app \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json")
  {
    PROD_REVOKED_APIKEY=$(echo $APP | jq -r ".credentials[0].consumerKey")
    PROD_REVOKED_APISECRET=$(echo $APP | jq -r ".credentials[0].consumerSecret")
    echo -e "\nPROD_REVOKED_APIKEY: $PROD_REVOKED_APIKEY"
    echo -e "\nPROD_REVOKED_APISECRET: $PROD_REVOKED_APISECRET"
  } || {
    echo -e "\nError extracting credentials from Application prod-unapproved-app: $STATUS_CODE"
    exit 8
  }
  if [[ -z $PROD_REVOKED_APIKEY ]] || [[ -z $PROD_REVOKED_APISECRET ]] ; then
    echo -e "\nError extracting credentials from Application prod-unapproved-app: $STATUS_CODE"
    exit 8
  fi

  echo -e "\nRevoking httpbin-product in prod-unapproved-app..."
  curl -X POST --silent -o /dev/stderr -w "%{http_code}" \
    "https://${MGMT}/v1/organizations/${ORG}/developers/integration@test.com/apps/prod-unapproved-app/keys/${PROD_REVOKED_APIKEY}/apiproducts/httpbin-product?action=revoke" \
    -d "" -H "Authorization: Bearer ${TOKEN}"
}

################################################################################
# Undeploy remote-service API Proxies
################################################################################
function undeployRemoteServiceProxies {
  if [[ -z $1 ]] ; then
    env=$ENV
  else
    env=$1
  fi

  if [[ -z $2 ]] ; then
    runtime=$RUNTIME
  else
    runtime=$2
  fi

  TOKEN=$(gcloud auth print-access-token)
  echo -e "\nGet deployed revision of API Proxies remote-service..."
  REV=$(docker run curlimages/curl:7.72.0 --silent \
    https://${MGMT}/v1/organizations/${ORG}/apis/remote-service/deployments \
    -H "Authorization: Bearer ${TOKEN}" | jq -r --arg env "${env}" '.deployments[] | select(.environment==$env) | .revision')
  echo -e "\nGot deployed revision $REV"

  if [[ ! -z $REV ]] ; then
    echo -e "\nUndeploying revision $REV of API Proxies remote-service..."
    STATUS_CODE=$(docker run curlimages/curl:7.72.0 -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
      https://${MGMT}/v1/organizations/${ORG}/environments/${env}/apis/remote-service/revisions/${REV}/deployments \
      -H "Authorization: Bearer ${TOKEN}")
    if [[ $STATUS_CODE -ge 299 ]] ; then
      echo -e "\nError undeploying API Proxies remote-service: $STATUS_CODE"
    fi
  fi

  for i in {1..20}
  do
    STATUS_CODE=$(curl --silent -o /dev/stderr -w "%{http_code}" \
     $runtime/remote-service/version)
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
  if [[ -z $2 ]] ; then
    env=$ENV
  else
    env=$2
  fi

  if [[ -z $3 ]] ; then
    runtime=$RUNTIME
  else
    runtime=$3
  fi

  if [[ ! -z $1 ]] ; then
    TOKEN=$(gcloud auth print-access-token)
    echo -e "\nDeploying revision $1 of API Proxies remote-service..."
    STATUS_CODE=$(docker run curlimages/curl:7.72.0 -X POST --silent -o /dev/stderr -w "%{http_code}" \
      https://${MGMT}/v1/organizations/${ORG}/environments/${env}/apis/remote-service/revisions/$1/deployments \
      -H "Authorization: Bearer ${TOKEN}")
    if [[ $STATUS_CODE -ge 299 ]] ; then
      echo -e "\nError undeploying API Proxies remote-service: $STATUS_CODE"
    fi
  fi

  for i in {1..20}
  do
    STATUS_CODE=$(curl --silent -o /dev/stderr -w "%{http_code}" \
     $runtime/remote-service/version)
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

  gcloud iam service-accounts add-iam-policy-binding \
    --role roles/iam.workloadIdentityUser \
    --member "serviceAccount:${PROJECT}.svc.id.goog[apigee/apigee-remote-service-envoy]" \
    apigee-udca@${PROJECT}.iam.gserviceaccount.com

  kubectl annotate serviceaccount --overwrite \
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

  echo -e "\nDeleting Application cred-exp-app..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/developers/integration@test.com/apps/cred-exp-app \
    -H "Authorization: Bearer ${TOKEN}")
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting Application cred-exp-app: $STATUS_CODE"
  fi

  echo -e "\nDeleting Application unapproved-app..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/developers/integration@test.com/apps/unapproved-app \
    -H "Authorization: Bearer ${TOKEN}")
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting Application unapproved-app: $STATUS_CODE"
  fi

  echo -e "\nDeleting Application prod-unapproved-app..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/developers/integration@test.com/apps/prod-unapproved-app \
    -H "Authorization: Bearer ${TOKEN}")
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting Application prod-unapproved-app: $STATUS_CODE"
  fi

  echo -e "\nDeleting Application wrong-prod-app..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/developers/integration@test.com/apps/wrong-prod-app \
    -H "Authorization: Bearer ${TOKEN}")
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting Application wrong-prod-app: $STATUS_CODE"
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

  echo -e "\nDeleting API Product opgrp-product..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/apiproducts/opgrp-product \
    -H "Authorization: Bearer ${TOKEN}")
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting API Product opgrp-product: $STATUS_CODE"
  fi

  echo -e "\nDeleting API Product dummy-product..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/apiproducts/dummy-product \
    -H "Authorization: Bearer ${TOKEN}")
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting API Product dummy-product: $STATUS_CODE"
  fi

  undeployRemoteServiceProxies $ENV $RUNTIME
  undeployRemoteServiceProxies $ENV2 $RUNTIME2

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
. ${BUILD_DIR}/scripts/lib.sh

setEnvironmentVariables hybrid-env

{
  cleanUpApigee
} || {
  echo -e "\n Apigee resources do not all exist."
}

pushDockerImages $ADAPTER_IMAGE_TAG
provisionRemoteService

echo -e "\nTesting Apigee Envrionment $ENV and Runtime $RUNTIME..."
cp config1.yaml config.yaml

generateIstioSampleConfigurations $HYBRID_ISTIO_TEMPLATE $ADAPTER_IMAGE_TAG

cleanUpKubernetes

applyToCluster istio-samples
runIstioTests

runAdditionalIstioTests

ENV=$ENV2
RUNTIME=$RUNTIME2
echo -e "\nTesting Apigee Envrionment $ENV and Runtime $RUNTIME..."
cp config2.yaml config.yaml

generateIstioSampleConfigurations $HYBRID_ISTIO_TEMPLATE $ADAPTER_IMAGE_TAG

cleanUpKubernetes

applyToCluster istio-samples
runIstioTests

echo -e "\nFinished integration test of the Apigee Envoy Adapter with Apigee Hybrid."

