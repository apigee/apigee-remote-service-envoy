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

# Display commands
set -x

################################################################################
# Provisioning remote-service
################################################################################
function provisionRemoteService {
  echo -e "\nProvisioning via CLI..."
  TOKEN=$(gcloud auth print-access-token)
  MGMTURL=https://apigee.googleapis.com

  {
    $CLI provision -o $ORG -e $ENV -t $TOKEN -r $RUNTIME -f -v > config1.yaml
    $CLI provision -o $ORG -e $ENV2 -t $TOKEN -r $RUNTIME2 -v > config2.yaml
  } || { # exit directly if cli encounters any error
    exit 8
  }

  createAPIProduct httpbin-product hybrid_product
  createAPIProduct opgrp-product opgrp_product
  createAPIProduct dummy-product dummy_product
  createAPIProduct httpbin-product-prod httpbin_product_prod

  createDeveloper integration@test.com developer

  createApplication httpbin-app hybrid_app
  createApplication wrong-prod-app wrong-prod_app
  createApplication cred-exp-app cred-expired_app
  createApplication unapproved-app unapproved_app
  createApplication prod-unapproved-app prod-unapproved_app

  fetchAppCredentials httpbin-app integration@test.com
  APIKEY=$KEY
  APISECRET=$SECRET

  fetchAppCredentials wrong-prod-app integration@test.com
  WRONG_APIKEY=$KEY
  WRONG_APISECRET=$SECRET

  fetchAppCredentials cred-exp-app integration@test.com
  EXPIRED_APIKEY=$KEY
  EXPIRED_APISECRET=$SECRET

  fetchAppCredentials unapproved-app integration@test.com
  REVOKED_APIKEY=$KEY
  REVOKED_APISECRET=$SECRET

  fetchAppCredentials prod-unapproved-app integration@test.com
  PROD_REVOKED_APIKEY=$KEY
  PROD_REVOKED_APISECRET=$SECRET

  echo -e "\nRevoking httpbin-product in prod-unapproved-app..."
  curl -X POST --silent -o /dev/stderr -w "%{http_code}" \
    "${MGMTURL}/v1/organizations/${ORG}/developers/integration@test.com/apps/prod-unapproved-app/keys/${PROD_REVOKED_APIKEY}/apiproducts/httpbin-product?action=revoke" \
    -d "" -H "Authorization: Bearer ${TOKEN}"
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
  MGMTURL=https://apigee.googleapis.com

  deleteApplication httpbin-app integration@test.com
  deleteApplication cred-exp-app integration@test.com
  deleteApplication unapproved-app integration@test.com
  deleteApplication prod-unapproved-app integration@test.com
  deleteApplication wrong-prod-app integration@test.com

  deleteDeveloper integration@test.com

  deleteAPIProduct httpbin-product
  deleteAPIProduct dummy-product
  deleteAPIProduct opgrp-product
  deleteAPIProduct httpbin-product-prod

  undeployRemoteServiceProxies $ENV $RUNTIME
  undeployRemoteServiceProxies $ENV2 $RUNTIME2

  deleteAPIProxy remote-service
}

echo -e "\nStarting integration test of the Apigee Envoy Adapter with Apigee Hybrid..."

# load necessary function definitions
. ${BUILD_DIR}/scripts/test_lib.sh
. ${BUILD_DIR}/scripts/util_lib.sh
. ${BUILD_DIR}/scripts/hybrid_lib.sh

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


