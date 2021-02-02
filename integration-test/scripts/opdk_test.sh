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
  {
    $CLI provision -o $ORG -e $ENV -u $USER -p $PASSWORD --opdk \
      --management $MGMTURL --runtime $RUNTIME \
      --virtual-hosts default -f > config.yaml
    chmod 644 config.yaml
  } || { # exit directly if cli encounters any error
    exit 9
  }

  createAPIProduct httpbin-product httpbin_product
  createAPIProduct dummy-product dummy_product

  createDeveloper integration@test.com developer

  createApplication httpbin-app application
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
    -u $USER:$PASSWORD
}

################################################################################
# Clean up Apigee resources
################################################################################
function cleanUpApigee {
  echo -e "\nCleaning up resources applied to the Apigee OPDK..."

  deleteApplication httpbin-app integration@test.com
  deleteApplication cred-exp-app integration@test.com
  deleteApplication unapproved-app integration@test.com
  deleteApplication prod-unapproved-app integration@test.com
  deleteApplication wrong-prod-app integration@test.com

  deleteDeveloper integration@test.com

  deleteAPIProduct httpbin-product
  deleteAPIProduct dummy-product

  undeployRemoteServiceProxies
  undeployAPIProxies edgemicro-internal

  deleteAPIProxy remote-service
  deleteAPIProxy edgemicro-internal
}

echo -e "\nStarting integration test of the Apigee Envoy Adapter with Apigee OPDK..."

# load necessary function definitions
. ${BUILD_DIR}/scripts/test_lib.sh
. ${BUILD_DIR}/scripts/util_lib.sh
. ${BUILD_DIR}/scripts/legacy_lib.sh

setEnvironmentVariables opdk-env

{
  cleanUpApigee
  docker stop envoy
  docker stop adapter
} || {
  echo -e "\n Apigee resources do not all exist."
}

provisionRemoteService

generateEnvoySampleConfigurations $OPDK_ENVOY_TEMPLATE

runEnvoyTests $OPDK_ENVOY_TAG $ADAPTER_IMAGE_TAG

echo -e "\nFinished integration test of the Apigee Envoy Adapter with Apigee OPDK."