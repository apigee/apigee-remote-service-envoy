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
  echo -e "\nSetting up environment variables from the GCP secret cgsaas-env..."
  gcloud secrets versions access 1 --secret="cgsaas-env" > cgsaas-env
  source ./cgsaas-env

  CLI=${KOKORO_ARTIFACTS_DIR}/github/apigee-remote-service-cli/apigee-remote-service-cli
  #CLI=$HOME/repos/apigee-remote-service-cli/dist/default_linux_amd64/apigee-remote-service-cli
  MGMT=api.enterprise.apigee.com
  REPO=${KOKORO_ARTIFACTS_DIR}/github/apigee-remote-service-envoy
  #REPO=$HOME/repos/apigee-remote-service-envoy
  echo -e "\nGetting Hybrid cluster credentials and configuring kubectl..."
  gcloud container clusters get-credentials $CLUSTER --zone $ZONE --project $PROJECT
}

################################################################################
# Provisioning remote-service
################################################################################
function provisionRemoteService {
  echo -e "\nProvisioning via CLI..."

  {
    $CLI provision -o $ORG -e $ENV -u $USER -p $PASSWORD --legacy -f > config.yaml
    chmod 644 config.yaml
  } || { # clean up and exit directly if cli encounters any error
    cleanUp
    exit 1
  }

  echo -e "\nCreating API Product httpbin-product..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}"\
    https://api.enterprise.apigee.com/v1/organizations/${ORG}/apiproducts \
    -u $USER:$PASSWORD \
    -H "Content-Type: application/json" \
    -d @${REPO}/kokoro/scripts/httpbin_product.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError creating API Product httpbin-product: $STATUS_CODE"
    cleanUp
    exit 1
  fi  

  echo -e "\nCreating Application Developer integration@test.com..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/developers \
    -u $USER:$PASSWORD \
    -H "Content-Type: application/json" \
    -d @${REPO}/kokoro/scripts/developer.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError creating Application Developer integration@test.com: $STATUS_CODE"
    cleanUp
    exit 1
  fi

  echo -e "\nCreating Application httpbin-app..."
  STATUS_CODE=$(curl -X POST --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/developers/integration@test.com/apps \
    -u $USER:$PASSWORD \
    -H "Content-Type: application/json" \
    -d @${REPO}/kokoro/scripts/application.json)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError creating Application httpbin-app: $STATUS_CODE"
    cleanUp
    exit 1
  fi

  echo -e "\nExtracting Application httpbin-app credentials..."
  APP=$(curl --silent \
    https://${MGMT}/v1/organizations/${ORG}/developers/integration@test.com/apps/httpbin-app \
    -u $USER:$PASSWORD \
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
    $CLI samples create -c config.yaml --out istio-samples --template $1 --tag test
    sed -i -e "s/google/gcr.io\/${PROJECT}/g" istio-samples/apigee-envoy-adapter.yaml
    $CLI samples create -c config.yaml --out native-samples --template native --tag test
    chmod 644 native-samples/envoy-config.yaml
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
  kubectl apply -f istio-samples
}

################################################################################
# Undeploy remote-service API Proxies
################################################################################
function undeployRemoteServiceProxies {
  TOKEN=$(gcloud auth print-access-token)
  echo -e "\nGet deployed revision of API Proxies remote-service..."
  REV=$(docker run curlimages/curl:7.72.0 --silent \
    https://${MGMT}/v1/organizations/${ORG}/apis/remote-service \
    -u $USER:$PASSWORD | jq -r ".revision | max")
  echo -e "\nGot deployed revision $REV"

  if [[ ! -z $REV ]] ; then
    echo -e "\nUndeploying revision $REV of API Proxies remote-service..."
    STATUS_CODE=$(docker run curlimages/curl:7.72.0 -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
      https://${MGMT}/v1/organizations/${ORG}/environments/${ENV}/apis/remote-service/revisions/${REV}/deployments \
      -u $USER:$PASSWORD)
    if [[ $STATUS_CODE -ge 299 ]] ; then
      echo -e "\nError undeploying API Proxies remote-service: $STATUS_CODE"
    fi
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
      https://${MGMT}/v1/organizations/${ORG}/environments/${ENV}/apis/remote-service/revisions/$1/deployments \
      -u $USER:$PASSWORD)
    if [[ $STATUS_CODE -ge 299 ]] ; then
      echo -e "\nError undeploying API Proxies remote-service: $STATUS_CODE"
    fi
  fi
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
      cleanUp
      exit 1
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
      cleanUp
      exit 1
    else 
      echo -e "\nCalling local target with JWT got $STATUS_CODE as expected"
    fi
  else
    echo -e "\nCalling local target with JWT got $STATUS_CODE"
  fi
}

################################################################################
# Run actual tests with native Envoy
################################################################################
function runEnvoyTests {
  echo -e "\nStarting to run tests with native Envoy..."
  {
    echo -e "\nStarting Envoy docker image..."
    docker run -v $PWD/native-samples/envoy-config.yaml:/envoy.yaml \
      --name=envoy --network=host --rm -d \
      docker.io/envoyproxy/envoy:v1.16.0 -c /envoy.yaml -l debug

    echo -e "\nStarting Adapter docker image..."
    docker run -v $PWD/config.yaml:/config.yaml \
      --name=adapter -p 5000:5000 --rm -d \
      apigee-envoy-adapter:test -c /config.yaml -l DEBUG

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
      if [[ $STATUS_CODE -eq 403 ]] ; then
        echo -e "\nQuota depleted"
        break
      fi
      sleep 1
    done
    callTargetWithAPIKey $APIKEY 403
    
    sleep 65

    echo -e "\nQuota should have restored"
    callTargetWithAPIKey $APIKEY 200

    undeployRemoteServiceProxies

    for i in {1..20}
    do
      callTargetWithAPIKey $APIKEY
      if [[ $STATUS_CODE -eq 403 ]] ; then
        echo -e "\nLocal quota depleted"
        break
      fi
      sleep 1
    done
    callTargetWithAPIKey $APIKEY 403
    
    sleep 65
    
    echo -e "\nLocal quota should have restored"
    callTargetWithAPIKey $APIKEY 200

    deployRemoteServiceProxies $REV
  } || { # clean up resources on failure
    cleanUp
    exit 1
  }
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
      cleanUp
      exit 1
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
      cleanUp
      exit 1
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

  echo -e "\nDeleting Application httpbin-app..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/developers/integration@test.com/apps/httpbin-app \
    -u $USER:$PASSWORD)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting Application httpbin-app: $STATUS_CODE"
  fi

  echo -e "\nDeleting Application Developer integration@test.com..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/developers/integration@test.com \
    -u $USER:$PASSWORD)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting Application Developer integration@test.com: $STATUS_CODE"
  fi

  echo -e "\nDeleting API Product httpbin-product..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/apiproducts/httpbin-product \
    -u $USER:$PASSWORD)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting API Product httpbin-product: $STATUS_CODE"
  fi

  echo -e "\nDeleting API Product remote-service..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/apiproducts/remote-service \
    -u $USER:$PASSWORD)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting API Product remote-service: $STATUS_CODE"
  fi

  undeployRemoteServiceProxies

  echo -e "\nDeleting API Proxies remote-service..."
  STATUS_CODE=$(curl -X DELETE --silent -o /dev/stderr -w "%{http_code}" \
    https://${MGMT}/v1/organizations/${ORG}/apis/remote-service \
    -u $USER:$PASSWORD)
  if [[ $STATUS_CODE -ge 299 ]] ; then
    echo -e "\nError deleting API Proxies remote-service: $STATUS_CODE"
  fi

  echo -e "\nDeleting configuration files..."
  if [[ -f "cgsaas-env" ]]; then
    rm cgsaas-env
  fi
  if [[ -f "config.yaml" ]]; then
    {
      kubectl delete -f config.yaml
      rm config.yaml
    } || { # in the case of k8s deletion failure
      rm config.yaml
    }
  fi
  if [[ -d "istio-samples" ]]; then
    {
      kubectl delete -f istio-samples
      rm -r istio-samples
    } || { # in the case of k8s deletion failure
      rm -r istio-samples
    }
  fi
  if [[ -d "native-samples" ]]; then
    rm -r native-samples
  fi
  kubectl delete pods curl

  echo -e "\nStopping local Docker containers..."
  docker stop envoy
  docker stop adapter
  echo -e "\nContainers stopped."
}


echo -e "\nStarting integration test of the Apigee Envoy Adapter with Apigee SaaS..."

setEnvironmentVariables
provisionRemoteService
generateSampleConfigurations istio-1.7
runEnvoyTests
applyToCluster
runIstioTests
cleanUp

echo -e "\nFinished integration test of the Apigee Envoy Adapter with Apigee SaaS."