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
# Create API Product
################################################################################
function createAPIProduct {
  echo -e "\nCreating API Product ${1}..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}"\
    ${MGMTURL}/v1/organizations/${ORG}/apiproducts \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d @${REPO}/integration-test/payloads/${2}.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError creating API Product ${1}: $STATUS_CODE"
    exit 9
  fi  
}

################################################################################
# Create Developer
################################################################################
function createDeveloper {
  echo -e "\nCreating Application Developer ${1}..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}" \
    ${MGMTURL}/v1/organizations/${ORG}/developers \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d @${REPO}/integration-test/payloads/${2}.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError creating Application Developer ${1}: $STATUS_CODE"
    exit 9
  fi
}

################################################################################
# Create Application
################################################################################
function createApplication {
  developer=integration@test.com
  if [[ ! -z ${3} ]] ; then
    developer=${3}
  fi
  echo -e "\nCreating Application ${1}..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}" \
    ${MGMTURL}/v1/organizations/${ORG}/developers/${developer}/apps \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d @${REPO}/integration-test/payloads/${2}.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError creating Application ${1}: $STATUS_CODE"
    exit 9
  fi
}

################################################################################
# Fetch Application Key and Secret
################################################################################
function fetchAppCredentials {
  echo -e "\nExtracting Application ${1} credentials..."
  APP=$(curl --silent \
    ${MGMTURL}/v1/organizations/${ORG}/developers/${2}/apps/${1} \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json")
  {
    KEY=$(echo $APP | jq -r ".credentials[0].consumerKey")
    SECRET=$(echo $APP | jq -r ".credentials[0].consumerSecret")
  } || {
    echo -e "\nError extracting credentials from Application ${1}: $STATUS_CODE"
    exit 9
  }
  if [[ -z $KEY ]] || [[ -z $SECRET ]] ; then
    echo -e "\nError extracting credentials from Application ${1}: $STATUS_CODE"
    exit 9
  fi
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
      ${MGMTURL}/v1/organizations/${ORG}/environments/${env}/apis/remote-service/revisions/$1/deployments \
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
    ${MGMTURL}/v1/organizations/${ORG}/apis/remote-service/deployments \
    -H "Authorization: Bearer ${TOKEN}" | jq -r --arg env "${env}" '.deployments[] | select(.environment==$env) | .revision')
  echo -e "\nGot deployed revision $REV"

  if [[ ! -z $REV ]] ; then
    echo -e "\nUndeploying revision $REV of API Proxies remote-service..."
    STATUS_CODE=$(docker run curlimages/curl:7.72.0 -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
      ${MGMTURL}/v1/organizations/${ORG}/environments/${env}/apis/remote-service/revisions/${REV}/deployments \
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
# Delete Application
################################################################################
function deleteApplication {
  echo -e "\nDeleting Application ${1}..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    ${MGMTURL}/v1/organizations/${ORG}/developers/${2}/apps/${1} \
    -H "Authorization: Bearer ${TOKEN}")
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting Application ${1}: $STATUS_CODE"
  fi
}

################################################################################
# Delete API Developer
################################################################################
function deleteDeveloper {
  echo -e "\nDeleting Application Developer ${1}..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    ${MGMTURL}/v1/organizations/${ORG}/developers/${1} \
    -H "Authorization: Bearer ${TOKEN}")
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting Application Developer ${1}: $STATUS_CODE"
  fi
}

################################################################################
# Delete API Product
################################################################################
function deleteAPIProduct {
  echo -e "\nDeleting API Product ${1}..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    ${MGMTURL}/v1/organizations/${ORG}/apiproducts/${1} \
    -H "Authorization: Bearer ${TOKEN}")
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting API Product ${1}: $STATUS_CODE"
  fi
}

################################################################################
# Delete API Proxy
################################################################################
function deleteAPIProxy {
  echo -e "\nDeleting API Proxies ${1}..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    ${MGMTURL}/v1/organizations/${ORG}/apis/${1} \
    -H "Authorization: Bearer ${TOKEN}")
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting API Proxies ${1}: $STATUS_CODE"
  fi
}