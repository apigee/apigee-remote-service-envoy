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
# Build CLI from source code
################################################################################
function installPrerequisites {
  echo -e "\nInstalling jq..."
  sudo apt install jq -y

  echo -e "\nUpdating gcloud SDK..."
  gcloud components update --quiet

  echo -e "\nInstalling go 1.15..."
  if [[ -d "/usr/local/go" ]] ; then 
    sudo rm -r /usr/local/go
  fi
  curl -LO https://golang.org/dl/go1.15.6.linux-amd64.tar.gz
  sudo tar -C /usr/local -xzf go1.15.6.linux-amd64.tar.gz
  export PATH=$PATH:/usr/local/go/bin
  sudo chmod 777 /usr/local/go
}

################################################################################
# Build CLI from source code
################################################################################
function buildRemoteServiceCLI {
  echo -e "\nBuilding apigee-remote-service-cli..."
  cd ${REPOS_DIR}/apigee-remote-service-cli
  go mod download
  CGO_ENABLED=0 go build -a -o apigee-remote-service-cli .
  export CLI=${REPOS_DIR}/apigee-remote-service-cli/apigee-remote-service-cli
  cd -
}

################################################################################
# Build Adapter Docker Image from source code
################################################################################
function buildAdapterDocker {
  echo -e "\nBuilding local Docker image of apigee-remote-service-envoy..."
  cd ${REPOS_DIR}/apigee-remote-service-envoy
  docker build -t apigee-envoy-adapter:${ADAPTER_IMAGE_TAG} \
    --build-arg CGO_ENABLED=${GCO_ENABLED} \
    --build-arg RUN_CONTAINER=${RUN_CONTAINER} \
    --build-arg BUILD_CONTAINER=${BUILD_CONTAINER} \
    .
  cd -
}

################################################################################
# Fetching environment variables from secrets in the GCP project
################################################################################
function setEnvironmentVariables {
  echo -e "\nSetting up environment variables from the GCP secret ${1}..."
  gcloud secrets versions access 1 --secret="${1}" > ${1}
  source ./${1}
  REPO=${REPOS_DIR}/apigee-remote-service-envoy

  echo -e "\nGetting Kubernetes cluster credentials and configuring kubectl..."
  gcloud container clusters get-credentials $CLUSTER --zone $ZONE --project $PROJECT
}

################################################################################
# Pushing Docker images based on the latest source code
################################################################################
function pushDockerImages {
  echo -e "\nTagging and pushing the Docker image to gcr.io..."
  gcloud auth configure-docker gcr.io
  docker tag apigee-envoy-adapter:${1} gcr.io/${PROJECT}/apigee-envoy-adapter:${1}
  docker push gcr.io/${PROJECT}/apigee-envoy-adapter:${1}
  echo -e "\nDocker image pushed successfully."
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
    $CLI samples create -c config.yaml --out istio-samples --template $1 --tag $2 -f
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
  echo -e "\nGenerating sample configurations files for native Envoy via the CLI..."
  if [[ -d "native-samples" ]]; then
    rm -r native-samples
  fi
  {
    $CLI samples create -c config.yaml --out native-samples --template ${1} -f
    chmod 644 native-samples/envoy-config.yaml
  } || { # exit directly if cli encounters any error
    exit 1
  }
}

################################################################################
# Call Local Target With APIKey
################################################################################
function callTargetWithAPIKey {
  if [[ -z $3 ]] ; then
    HOST=httpbin.org
  else
    HOST=$3
  fi

  if [[ -z $4 ]] ; then
    RESOURCE_PATH=/headers
  else
    RESOURCE_PATH=$4
  fi

  if [[ -z $5 ]] ; then
    METHOD=GET
  else
    METHOD=$5
  fi

  STATUS_CODE=$(docker run --network=host curlimages/curl:7.72.0 -X $METHOD \
    --silent -o /dev/stderr -w "%{http_code}" \
    localhost:8080$RESOURCE_PATH -Hhost:$HOST \
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
  if [[ -z $3 ]] ; then
    HOST=httpbin.org
  else
    HOST=$3
  fi

  if [[ -z $4 ]] ; then
    RESOURCE_PATH=/headers
  else
    RESOURCE_PATH=$4
  fi

  if [[ -z $5 ]] ; then
    METHOD=GET
  else
    METHOD=$5
  fi

  STATUS_CODE=$(docker run --network=host curlimages/curl:7.72.0 -X $METHOD \
    --silent -o /dev/stderr -w "%{http_code}" \
    localhost:8080$RESOURCE_PATH -Hhost:$HOST \
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
  if [[ -z $3 ]] ; then
    HOST=httpbin.default.svc.cluster.local
  else
    HOST=$3
  fi

  if [[ -z $4 ]] ; then
    RESOURCE_PATH=/headers
  else
    RESOURCE_PATH=$4
  fi

  if [[ -z $5 ]] ; then
    METHOD=GET
  else
    METHOD=$5
  fi

  STATUS_CODE=$(kubectl exec curl -c curl -- \
    curl -X $METHOD --silent -o /dev/stderr -w "%{http_code}" \
    ${HOST}${RESOURCE_PATH} \
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
  if [[ -z $3 ]] ; then
    HOST=httpbin.default.svc.cluster.local
  else
    HOST=$3
  fi

  if [[ -z $4 ]] ; then
    RESOURCE_PATH=/headers
  else
    RESOURCE_PATH=$4
  fi

  if [[ -z $5 ]] ; then
    METHOD=GET
  else
    METHOD=$5
  fi

  STATUS_CODE=$(kubectl exec curl -c curl -- \
    curl -X $METHOD --silent -o /dev/stderr -w "%{http_code}" \
    ${HOST}${RESOURCE_PATH} \
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
# Run actual tests with native Envoy
################################################################################
function runEnvoyTests {
  echo -e "\nStarting to run tests with native Envoy..."
  {
    echo -e "\nStarting Envoy docker image..."
    docker run -v $PWD/native-samples/envoy-config.yaml:/envoy.yaml \
      --name=envoy --network=host --rm -d \
      docker.io/envoyproxy/envoy:${1} -c /envoy.yaml -l debug

    echo -e "\nStarting Adapter docker image..."
    docker run -v $PWD/config.yaml:/config.yaml \
      --name=adapter -p 5000:5000 --rm -d \
      apigee-envoy-adapter:${2} -c /config.yaml -l DEBUG

    for i in {1..20}
    do
      JWT=$($CLI token create -c config.yaml -i $APIKEY -s $APISECRET)
      sleep 30 # skew for JWT
      callTargetWithJWT $JWT
      sleep 30 # best effort to restore the quota
      if [[ $STATUS_CODE -eq 200 ]] ; then
        sleep 30 # best effort to restore the quota
        echo -e "\nServices are ready to be tested"
        break
      fi
    done

    echo -e "\nCalling with a good key"
    callTargetWithAPIKey $APIKEY 200
    echo -e "\nCalling with an bad string"
    callTargetWithAPIKey APIKEY 403
    echo -e "\nCalling with an expired key"
    callTargetWithAPIKey $EXPIRED_APIKEY 403
    echo -e "\nCalling with a key with wrong API Product"
    callTargetWithAPIKey $WRONG_APIKEY 403
    echo -e "\nCalling with a key with revoked App"
    callTargetWithAPIKey $REVOKED_APIKEY 403
    echo -e "\nCalling with a key with revoked API Product"
    callTargetWithAPIKey $PROD_REVOKED_APIKEY 403

    JWT=$($CLI token create -c config.yaml -i $EXPIRED_APIKEY -s $EXPIRED_APISECRET)
    if [[ ! -z $JWT ]] ; then
      echo "\nShould NOT have got a JWT from expired key and secret"
      exit 5
    fi

    JWT=$($CLI token create -c config.yaml -i $WRONG_APIKEY -s $WRONG_APISECRET)
    if [[ -z $JWT ]] ; then
      echo "\nShould have got a JWT from wrong key and secret"
      exit 5
    fi
    sleep 30 # skew for JWT
    echo -e "\nCalling with a JWT with wrong API Product"
    callTargetWithJWT $JWT 403

    JWT=$($CLI token create -c config.yaml -i $REVOKED_APIKEY -s $REVOKED_APISECRET)
    if [[ ! -z $JWT ]] ; then
      echo "\nShould NOT have got a JWT from key and secret of revoked App"
      exit 5
    fi

    JWT=$($CLI token create -c config.yaml -i $PROD_REVOKED_APIKEY -s $PROD_REVOKED_APISECRET)
    if [[ ! -z $JWT ]] ; then
      echo "\nShould NOT have got a JWT from key and secret of App with revoked API Product"
      exit 5
    fi

    for i in {1..20}
    do
      callTargetWithAPIKey $APIKEY
      if [[ $STATUS_CODE -eq 403 ]] ; then
        echo -e "\nQuota depleted"
        break
      fi
      sleep 1
    done
    if [[ $STATUS_CODE -ne 403 ]] ; then
      echo -e "\nQuota was not exhausted"
      exit 2
    fi
    
    sleep 65

    echo -e "\nQuota should have restored"
    callTargetWithAPIKey $APIKEY 200

    undeployRemoteServiceProxies $ENV $RUNTIME

    for i in {1..20}
    do
      callTargetWithAPIKey $APIKEY
      if [[ $STATUS_CODE -eq 403 ]] ; then
        echo -e "\nLocal quota depleted"
        break
      fi
      sleep 1
    done
    if [[ $STATUS_CODE -ne 403 ]] ; then
      echo -e "\nQuota was not exhausted"
      exit 2
    fi
    
    sleep 65
    
    echo -e "\nLocal quota should have restored"
    callTargetWithAPIKey $APIKEY 200

    deployRemoteServiceProxies $REV $ENV $RUNTIME
  } || { # exit on failure
    exit 7
  }
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
      sleep 30 # skew for JWT
      callIstioTargetWithJWT $JWT
      sleep 30 # best effort to restore the quota
      if [[ $STATUS_CODE -eq 200 ]] ; then
        sleep 30 # best effort to restore the quota
        echo -e "\nServices are ready to be tested"
        break
      fi
    done

    echo -e "\nCalling with a good key"
    callIstioTargetWithAPIKey $APIKEY 200
    echo -e "\nCalling with an bad string"
    callIstioTargetWithAPIKey APIKEY 403
    echo -e "\nCalling with an expired key"
    callIstioTargetWithAPIKey $EXPIRED_APIKEY 403
    echo -e "\nCalling with a key with wrong API Product"
    callIstioTargetWithAPIKey $WRONG_APIKEY 403
    echo -e "\nCalling with a key with revoked App"
    callIstioTargetWithAPIKey $REVOKED_APIKEY 403
    echo -e "\nCalling with a key with revoked API Product"
    callIstioTargetWithAPIKey $PROD_REVOKED_APIKEY 403

    JWT=$($CLI token create -c config.yaml -i $EXPIRED_APIKEY -s $EXPIRED_APISECRET)
    if [[ ! -z $JWT ]] ; then
      echo "\nShould NOT have got a JWT from expired key and secret"
      exit 5
    fi

    JWT=$($CLI token create -c config.yaml -i $WRONG_APIKEY -s $WRONG_APISECRET)
    if [[ -z $JWT ]] ; then
      echo "\nShould have got a JWT from wrong key and secret"
      exit 5
    fi
    sleep 30
    echo -e "\nCalling with a JWT with wrong API Product"
    callIstioTargetWithJWT $JWT 403

    JWT=$($CLI token create -c config.yaml -i $REVOKED_APIKEY -s $REVOKED_APISECRET)
    if [[ ! -z $JWT ]] ; then
      echo "\nShould NOT have got a JWT from key and secret of revoked App"
      exit 5
    fi

    JWT=$($CLI token create -c config.yaml -i $PROD_REVOKED_APIKEY -s $PROD_REVOKED_APISECRET)
    if [[ ! -z $JWT ]] ; then
      echo "\nShould NOT have got a JWT from key and secret of App with revoked API Product"
      exit 5
    fi
    
    for i in {1..20}
    do
      callIstioTargetWithAPIKey $APIKEY
      if [[ $STATUS_CODE -eq 403 ]] ; then
        echo -e "\nQuota depleted"
        break
      fi
      sleep 1
    done
    if [[ $STATUS_CODE -ne 403 ]] ; then
      echo -e "\nQuota was not exhausted"
      exit 4
    fi
    
    sleep 65

    echo -e "\nQuota should have restored"
    callIstioTargetWithAPIKey $APIKEY 200

    undeployRemoteServiceProxies $ENV $RUNTIME

    for i in {1..20}
    do
      callIstioTargetWithAPIKey $APIKEY
      if [[ $STATUS_CODE -eq 403 ]] ; then
        echo -e "\nLocal quota depleted"
        break
      fi
      sleep 1
    done
    if [[ $STATUS_CODE -ne 403 ]] ; then
      echo -e "\nQuota was not exhausted"
      exit 4
    fi
    
    sleep 65
    
    echo -e "\nLocal quota should have restored"
    callIstioTargetWithAPIKey $APIKEY 200

    deployRemoteServiceProxies $REV $ENV $RUNTIME
  } || { # exit on failure
    exit 6
  }
}

################################################################################
# Run additional tests regarding API Product Operation Group on Istio
################################################################################
function runAdditionalIstioTests {
  echo -e "\nStarting to run tests on Istio..."
  {
    echo -e "\nCalling /get with GET"
    callIstioTargetWithAPIKey $APIKEY 200 httpbin.default.svc.cluster.local /get GET
    echo -e "\nCalling /post with POST"
    callIstioTargetWithAPIKey $APIKEY 200 httpbin.default.svc.cluster.local /post POST
    echo -e "\nCalling /get with POST"
    callIstioTargetWithAPIKey $APIKEY 403 httpbin.default.svc.cluster.local /get POST
    echo -e "\nCalling /post with GET"
    callIstioTargetWithAPIKey $APIKEY 403 httpbin.default.svc.cluster.local /post GET
    
    for i in {1..20}
    do
      callIstioTargetWithAPIKey $APIKEY "" httpbin.default.svc.cluster.local /get GET
      if [[ $STATUS_CODE -eq 403 ]] ; then
        echo -e "\nQuota for /get depleted"
        break
      fi
      sleep 1
    done
    # echo -e "\nTesting quota for /post which should be unaffected..."
    # callIstioTargetWithAPIKey $APIKEY 200 httpbin.default.svc.cluster.local /post POST
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
