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
  echo -e "\nSetting up environment variables from the GCP secret ${1}..."
  gcloud secrets versions access 1 --secret="${1}" > ${1}
  source ./${1}
  CLI=${KOKORO_ARTIFACTS_DIR}/github/apigee-remote-service-cli/apigee-remote-service-cli
  REPO=${KOKORO_ARTIFACTS_DIR}/github/apigee-remote-service-envoy

  echo -e "\nGetting Kubernetes cluster credentials and configuring kubectl..."
  gcloud container clusters get-credentials $CLUSTER --zone $ZONE --project $PROJECT
}

################################################################################
# Building Docker images based on the latest source code
################################################################################
function buildDockerImages {
  echo -e "\nBuilding the Docker image to gcr.io..."
  gcloud builds submit -t gcr.io/${PROJECT}/apigee-envoy-adapter:test ${REPO}
  echo -e "\nDocker image built successfully."
}

################################################################################
# Generating sample configurations for Istio
################################################################################
function generateIstioSampleConfigurations {
  echo -e "\nGenerating sample configurations files for $1 via the CLI..."
  if [[ -d "istio-samples" ]]; then
    rm -r istio-samples
  fi
  {
    $CLI samples create -c config.yaml --out istio-samples --template $1 --tag test
    sed -i -e "s/google/gcr.io\/${PROJECT}/g" istio-samples/apigee-envoy-adapter.yaml
    sed -i -e "s/IfNotPresent/Always/g" istio-samples/apigee-envoy-adapter.yaml
  } || { # exit directly if cli encounters any error
    exit 1
  }
}

################################################################################
# Generating sample configurations for native Envoy
################################################################################
function generateEnvoySampleConfigurations {
  echo -e "\nGenerating sample configurations files for $1 via the CLI..."
  if [[ -d "native-samples" ]]; then
    rm -r native-samples
  fi
  {
    $CLI samples create -c config.yaml --out native-samples --template native --tag test
    chmod 644 native-samples/envoy-config.yaml
  } || { # exit directly if cli encounters any error
    exit 1
  }
}

################################################################################
# Call Local Target With APIKey
################################################################################
function callTargetWithAPIKey {
  STATUS_CODE=$(docker run --network=host curlimages/curl:7.72.0 --silent -o /dev/stderr -w "%{http_code}" \
    localhost:8080/headers -Hhost:httpbin.org \
    -Hx-api-key:$1)

  if [[ ! -z $2 ]] ; then
    if [[ $STATUS_CODE -ne $2 ]] ; then
      echo -e "\nError calling local target with API key: expected status $2; got $STATUS_CODE"
      exit 2
    else 
      echo -e "\nCalling local target with API key got $STATUS_CODE as expected"
    fi
  else
    echo -e "\nCalling local target with API key got $STATUS_CODE"
  fi
}

################################################################################
# call Local Target With JWT
################################################################################
function callTargetWithJWT {
  STATUS_CODE=$(docker run --network=host curlimages/curl:7.72.0 --silent -o /dev/stderr -w "%{http_code}" \
    localhost:8080/headers -Hhost:httpbin.org \
    -H "Authorization: Bearer $1")

  if [[ ! -z $2 ]] ; then
    if [[ $STATUS_CODE -ne $2 ]] ; then
      echo -e "\nError calling local target with JWT: expected status $2; got $STATUS_CODE"
      exit 3
    else 
      echo -e "\nCalling local target with JWT got $STATUS_CODE as expected"
    fi
  else
    echo -e "\nCalling local target with JWT got $STATUS_CODE"
  fi
}

################################################################################
# Call Target on Istio With APIKey
################################################################################
function callIstioTargetWithAPIKey {
  STATUS_CODE=$(kubectl exec curl -c curl -- \
    curl --silent -o /dev/stderr -w "%{http_code}" \
    httpbin.default.svc.cluster.local/headers \
    -Hx-api-key:$1)

  if [[ ! -z $2 ]] ; then
    if [[ $STATUS_CODE -ne $2 ]] ; then
      echo -e "\nError calling target with API key: expected status $2; got $STATUS_CODE"
      exit 4
    else 
      echo -e "\nCalling target with API key got $STATUS_CODE as expected"
    fi
  else
    echo -e "\nCalling target with API key got $STATUS_CODE"
  fi
}

################################################################################
# call Target on Istio With JWT
################################################################################
function callIstioTargetWithJWT {
  STATUS_CODE=$(kubectl exec curl -c curl -- \
    curl --silent -o /dev/stderr -w "%{http_code}" \
    httpbin.default.svc.cluster.local/headers \
    -H "Authorization: Bearer $1")

  if [[ ! -z $2 ]] ; then
    if [[ $STATUS_CODE -ne $2 ]] ; then
      echo -e "\nError calling target with JWT: expected status $2; got $STATUS_CODE"
      exit 5
    else 
      echo -e "\nCalling target with JWT got $STATUS_CODE as expected"
    fi
  else
    echo -e "\nCalling target with JWT got $STATUS_CODE"
  fi
}

################################################################################
# Run actual tests on Istio
################################################################################
function runIstioTests {
  echo -e "\nStarting to run tests on Istio..."
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
      callIstioTargetWithJWT $JWT
      sleep 60
      if [[ $STATUS_CODE -eq 200 ]] ; then
        echo -e "\nServices are ready to be tested"
        break
      fi
    done

    callIstioTargetWithAPIKey $APIKEY 200
    callIstioTargetWithAPIKey APIKEY 403
    for i in {1..20}
    do
      callIstioTargetWithAPIKey $APIKEY
      if [[ $STATUS_CODE -eq 403 ]] ; then
        echo -e "\nQuota depleted"
        break
      fi
      sleep 1
    done
    callIstioTargetWithAPIKey $APIKEY 403
    
    sleep 65

    echo -e "\nQuota should have restored"
    callIstioTargetWithAPIKey $APIKEY 200

    undeployRemoteServiceProxies

    for i in {1..20}
    do
      callIstioTargetWithAPIKey $APIKEY
      if [[ $STATUS_CODE -eq 403 ]] ; then
        echo -e "\nLocal quota depleted"
        break
      fi
      sleep 1
    done
    callIstioTargetWithAPIKey $APIKEY 403
    
    sleep 65
    
    echo -e "\nLocal quota should have restored"
    callIstioTargetWithAPIKey $APIKEY 200

    deployRemoteServiceProxies $REV
  } || { # exit on failure
    exit 6
  }
}

################################################################################
# Clean up Apigee resources
################################################################################
function cleanUpKubernetes {
  if [[ -f "config.yaml" ]]; then
    {
      kubectl delete -f config.yaml
    } || {
      echo -e "\nconfig map does not exist."
    }
  fi
  if [[ -d "istio-samples" ]]; then
    { kubectl delete -f istio-samples
    } || {
      echo -e "\n istio sample configurations do not exist."
    }
  fi
  {
    kubectl delete pods curl
  } || {
    echo -e "\n pod curl does not exist."
  }
}
