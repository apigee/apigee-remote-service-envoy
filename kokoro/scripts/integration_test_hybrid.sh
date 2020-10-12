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
  echo -e "\nSetting up environment variables from the GCP secret..."
  gcloud secrets versions access 1 --secret="hybrid-env" > hybrid-env
  source ./hybrid-env

  echo -e "\nGetting Hybrid cluster credentials and configuring kubectl..."
  gcloud container clusters get-credentials $CLUSTER --zone $ZONE --project $PROJECT
}

################################################################################
# Build CLI from source code
################################################################################
function buildRemoteServiceCLI {
  echo -e "\nBuilding apigee-remote-service-cli..."
  cd ${KOKORO_ARTIFACTS_DIR}/github/apigee-remote-service-cli
  sudo go mod download
  sudo CGO_ENABLED=0 go build -a -o apigee-remote-service-cli .
  CLI=$PWD/apigee-remote-service-cli
  cd -
}

################################################################################
# Building Docker images based on the latest source code
################################################################################
function buildDockerImages {
  echo -e "\nBuilding the Docker image to gcr.io..."
  gcloud builds submit -t gcr.io/${PROJECT}/apigee-envoy-adapter:test ${KOKORO_ARTIFACTS_DIR}/github/apigee-remote-service-envoy
  echo -e "\nDocker image built successfully."
}

################################################################################
# Provisioning remote-service
################################################################################
function provisionRemoteService {
  echo -e "\nProvisioning via CLI..."
  TOKEN=$(gcloud auth print-access-token)

  {
    $CLI provision -o $ORG -e $ENV -t $TOKEN -r $RUNTIME -f -v > config.yaml
  } || { # clean up and exit directly if cli encounters any error
    cleanUp
    exit 1
  }

  echo -e "\nCreating API Product httpbin-product..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}"\
    https://apigee.googleapis.com/v1/organizations/${ORG}/apiproducts \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d @httpbin_product.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError creating API Product httpbin-product: $STATUS_CODE"
    cleanUp
    exit 1
  fi  

  echo -e "\nCreating Application Developer integration@test.com..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}" \
    https://apigee.googleapis.com/v1/organizations/${ORG}/developers \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d @developer.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError creating Application Developer integration@test.com: $STATUS_CODE"
    cleanUp
    exit 1
  fi

  echo -e "\nCreating Application httpbin-app..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}" \
    https://apigee.googleapis.com/v1/organizations/${ORG}/developers/integration@test.com/apps \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d @application.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError creating Application httpbin-app: $STATUS_CODE"
    cleanUp
    exit 1
  fi

  echo -e "\nExtracting Application httpbin-app credentials..."
  APP=$(curl --silent \
    https://apigee.googleapis.com/v1/organizations/${ORG}/developers/integration@test.com/apps/httpbin-app \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json")
  {
    APIKEY=$(echo $APP | jq -r ".credentials[0].consumerKey")
    APISECRET=$(echo $APP | jq -r ".credentials[0].consumerSecret")
    echo -e "\nAPIKEY: $APIKEY"
    echo -e "\nAPISECRET: $APISECRET"
  } || {
    echo -e "\nError extracting credentials from Application httpbin-app: $STATUS_CODE"
    cleanUp
    exit 1
  }
  if [[ -z $APIKEY ]] || [[ -z $APISECRET ]] ; then
    echo -e "\nError extracting credentials from Application httpbin-app: $STATUS_CODE"
    cleanUp
    exit 1
  fi
}

################################################################################
# Generating sample configurations
################################################################################
function generateSampleConfigurations {
  echo -e "\nGenerating sample configurations files for $1 via the CLI..."

  {
    $CLI samples create -c config.yaml --out samples --template $1 --tag test
    sed -i -e "s/google/gcr.io\/${PROJECT}/g" samples/apigee-envoy-adapter.yaml
  } || { # clean up and exit directly if cli encounters any error
    cleanUp
    exit 1
  }
}

################################################################################
# Apply configurations
################################################################################
function applyToCluster {
  echo -e "\nDeploying config files to the cluster..."

  kubectl apply -f config.yaml
  kubectl apply -f samples
}

################################################################################
# Undeploy remote-service API Proxies
################################################################################
function undeployRemoteServiceProxies {
  TOKEN=$(gcloud auth print-access-token)
  echo -e "\nGet deployed revision of API Proxies remote-service..."
  REV=$(curl --silent \
    https://apigee.googleapis.com/v1/organizations/${ORG}/apis/remote-service/deployments \
    -H "Authorization: Bearer ${TOKEN}" | jq ".deployments[0].revision | tonumber")

  if [[ ! -z $REV ]] ; then
    echo -e "\nUndeploying revision $REV of API Proxies remote-service..."
    STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
      https://apigee.googleapis.com/v1/organizations/${ORG}/environments/${ENV}/apis/remote-service/revisions/${REV}/deployments \
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
    STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}" \
      https://apigee.googleapis.com/v1/organizations/${ORG}/environments/${ENV}/apis/remote-service/revisions/$1/deployments \
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
# callTargetWithAPIKey
################################################################################
function callTargetWithAPIKey {
  STATUS_CODE=$(kubectl exec curl -c curl -- \
    curl --silent -o /dev/stderr -w "%{http_code}" \
    httpbin.default.svc.cluster.local/headers \
    -Hx-api-key:$1)

  if [[ ! -z $2 ]] ; then
    if [[ $STATUS_CODE -ne $2 ]] ; then
      echo -e "\nError calling target: expected status $2; got $STATUS_CODE"
      cleanUp
      exit 1
    else 
      echo -e "\nCalling target got $STATUS_CODE as expected"
    fi
  else
    echo -e "\nCalling target got $STATUS_CODE"
  fi
}

################################################################################
# callTargetWithAPIKey
################################################################################
function callTargetWithJWT {
  STATUS_CODE=$(kubectl exec curl -c curl -- \
    curl --silent -o /dev/stderr -w "%{http_code}" \
    httpbin.default.svc.cluster.local/headers \
    -H "Authorization: Bearer $1")

  if [[ ! -z $2 ]] ; then
    if [[ $STATUS_CODE -ne $2 ]] ; then
      echo -e "\nError calling target: expected status $2; got $STATUS_CODE"
      cleanUp
      exit 1
    else 
      echo -e "\nCalling target got $STATUS_CODE as expected"
    fi
  else
    echo -e "\nCalling target got $STATUS_CODE"
  fi
}

################################################################################
# Run actual tests
################################################################################
function runTests {
  echo -e "\nStarting to run tests..."
  cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: curl
  labels:
    app: curl
spec:
  containers:
  - name: curl
    image: radial/busyboxplus:curl
    ports:
    - containerPort: 80
    command: ["/bin/sh", "-ec", "while :; do echo '.'; sleep 5 ; done"]
EOF

  {
    for i in {1..20}
    do
      JWT=$($CLI token create -c config.yaml -i $APIKEY -s $APISECRET)
      callTargetWithJWT $JWT
      sleep 60
      if [[ $STATUS_CODE -eq 200 ]] ; then
        echo -e "\nServices are ready to be tested"
        break
      fi
    done

    callTargetWithAPIKey $APIKEY 200
    callTargetWithAPIKey APIKEY 403
    for i in {1..20}
    do
      callTargetWithAPIKey $APIKEY
      sleep 1
      if [[ $STATUS_CODE -eq 403 ]] ; then
        echo -e "\nQuota depleted"
        break
      fi
    done
    callTargetWithAPIKey $APIKEY 403
    
    sleep 65

    echo -e "\nQuota should have restored"
    callTargetWithAPIKey $APIKEY 200

    undeployRemoteServiceProxies

    for i in {1..20}
    do
      callTargetWithAPIKey $APIKEY
      sleep 1
      if [[ $STATUS_CODE -eq 403 ]] ; then
        echo -e "\nQuota depleted"
        break
      fi
    done
    callTargetWithAPIKey $APIKEY 403
    
    sleep 65
    
    echo -e "\nQuota should have restored"
    callTargetWithAPIKey $APIKEY 200

    deployRemoteServiceProxies $REV
  } || { # clean up resources on failure
    cleanUp
    exit 1
  }
}

################################################################################
# Clean up
################################################################################
function cleanUp {
  echo -e "\nCleaning up resources applied to the Hybrid cluster..."
  TOKEN=$(gcloud auth print-access-token)

  echo -e "\nDeleting Application httpbin-app..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://apigee.googleapis.com/v1/organizations/${ORG}/developers/integration@test.com/apps/httpbin-app \
    -H "Authorization: Bearer ${TOKEN}")
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting Application httpbin-app: $STATUS_CODE"
  fi

  echo -e "\nDeleting Application Developer integration@test.com..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://apigee.googleapis.com/v1/organizations/${ORG}/developers/integration@test.com \
    -H "Authorization: Bearer ${TOKEN}")
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting Application Developer integration@test.com: $STATUS_CODE"
  fi

  echo -e "\nDeleting API Product httpbin-product..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://apigee.googleapis.com/v1/organizations/${ORG}/apiproducts/httpbin-product \
    -H "Authorization: Bearer ${TOKEN}")
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting API Product httpbin-product: $STATUS_CODE"
  fi

  echo -e "\nDeleting API Product remote-service..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://apigee.googleapis.com/v1/organizations/${ORG}/apiproducts/remote-service \
    -H "Authorization: Bearer ${TOKEN}")
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting API Product remote-service: $STATUS_CODE"
  fi

  undeployRemoteServiceProxies

  echo -e "\nDeleting API Proxies remote-service..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://apigee.googleapis.com/v1/organizations/${ORG}/apis/remote-service \
    -H "Authorization: Bearer ${TOKEN}")
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting API Proxies remote-service: $STATUS_CODE"
  fi

  echo -e "\nDeleting configuration files..."
  if [[ -f "config.yaml" ]]; then
    {
      kubectl delete -f config.yaml
      rm config.yaml
    } || { # in the case of k8s deletion failure
      rm config.yaml
    }
  fi
  if [[ -d "samples" ]]; then
    {
      kubectl delete -f samples
      rm -r samples
    } || { # in the case of k8s deletion failure
      rm -r samples
    }
  fi
  kubectl delete pods curl
}

echo -e "\nStarting integration test of the Apigee Envoy Adapter with Apigee Hybrid..."

setEnvironmentVariables
buildRemoteServiceCLI
buildDockerImages
provisionRemoteService
generateSampleConfigurations istio-1.6
applyToCluster
runTests
cleanUp

echo -e "\nFinished integration test of the Apigee Envoy Adapter with Apigee Hybrid."


