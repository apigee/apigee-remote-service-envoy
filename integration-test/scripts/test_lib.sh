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
    $CLI samples create -c config.yaml --out native-samples \
      --template ${1} --adapter-host adapter --host target \
      --port 8888 -f
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
# Call Local Target With APIKey in query param
################################################################################
function callTargetWithAPIKeyInQueryParam {
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
    "localhost:8080${RESOURCE_PATH}?x-api-key=${1}" -Hhost:$HOST)

  if [[ ! -z $2 ]] ; then
    if [[ $STATUS_CODE -ne $2 ]] ; then
      echo -e "\nError calling local target with API key in query param: expected status $2; got $STATUS_CODE"
      exit 2
    else 
      echo -e "\nCalling local target with API key in query param got $STATUS_CODE as expected"
    fi
  else
    echo -e "\nCalling local target with API key in query param got $STATUS_CODE"
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
# Call Local Target With JWT in query param
################################################################################
function callTargetWithJWTInQueryParam {
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
    "localhost:8080${RESOURCE_PATH}?jwt=${1}")

  if [[ ! -z $2 ]] ; then
    if [[ $STATUS_CODE -ne $2 ]] ; then
      echo -e "\nError calling local target with JWT in query param: expected status $2; got $STATUS_CODE"
      exit 3
    else 
      echo -e "\nCalling local target with JWT in query param got $STATUS_CODE as expected"
    fi
  else
    echo -e "\nCalling local target with JWT in query param got $STATUS_CODE"
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
# Start Envoy and Adapter docker containers
################################################################################
function startDockerContainer {
    docker network create apigee || echo "apigee net already exists."

    echo -e "\nStarting Envoy docker container..."
    docker run -v $PWD/native-samples/envoy-config.yaml:/envoy.yaml \
      --name=envoy --network=apigee \
      -p 8080:8080 --rm -d \
      docker.io/envoyproxy/envoy:${1} -c /envoy.yaml -l debug

    echo -e "\nStarting Adapter docker container..."
    docker run -v $PWD/config.yaml:/config.yaml \
      --name=adapter --network=apigee \
      -p 5000:5000 -p 5001:5001 --rm -d \
      apigee-envoy-adapter:${2} -c /config.yaml -l DEBUG

    echo -e "\nStarting Target docker container..."
    docker run -p 8888:8888 --rm -d \
      --name=target --network=apigee \
      apigee-target:test -addr 0.0.0.0:8888
}

################################################################################
# Start Envoy and Adapter docker containers for environment spec
################################################################################
function startDockerContainerForEnvSpec {
    docker network create apigee || echo "apigee net already exists."

    echo -e "\nStarting Envoy docker container..."
    docker run -v ${BUILD_DIR}/configs/envoy.yaml:/envoy.yaml \
      --name=envoy --network=apigee \
      -p 8080:8080 --rm -d \
      docker.io/envoyproxy/envoy:${1} -c /envoy.yaml -l debug

    echo -e "\nStarting Adapter docker container..."
    docker run -v $PWD/config.yaml:/config.yaml \
      -v ${BUILD_DIR}/configs/env_spec.yaml:/env_spec.yaml \
      --name=adapter --network=apigee \
      -p 5000:5000 -p 5001:5001 --rm -d \
      apigee-envoy-adapter:${2} -c /config.yaml --environment-specs /env_spec.yaml -l DEBUG

    echo -e "\nStarting Target docker container..."
    docker run -p 8888:8888 --rm -d \
      --name=target --network=apigee \
      apigee-target:test -addr 0.0.0.0:8888
}

################################################################################
# Run actual tests with native Envoy
################################################################################
function runEnvoyTests {
  echo -e "\nStarting to run tests with native Envoy..."
  {
    startDockerContainer ${1} ${2}

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
      if [[ $STATUS_CODE -eq 429 ]] ; then
        echo -e "\nQuota depleted"
        break
      fi
      sleep 1
    done
    if [[ $STATUS_CODE -ne 429 ]] ; then
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
      if [[ $STATUS_CODE -eq 429 ]] ; then
        echo -e "\nLocal quota depleted"
        break
      fi
      sleep 1
    done
    if [[ $STATUS_CODE -ne 429 ]] ; then
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
# Run Multi-env Test with Local Envoy
################################################################################
function runEnvoyMultiEnvTest {
  {
    sed -i -e "s/env_name: test/env_name: \"*\"/g" config.yaml

    cp native-samples/envoy-config.yaml native-samples/envoy-config.yaml.bak
    match="cluster: httpbin"
    insert="\n                typed_per_filter_config:\n                  envoy.filters.http.ext_authz:\n                    \"@type\": type.googleapis.com\/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute\n                    check_settings:\n                        context_extensions:\n                          apigee_environment: test"
    sed -i -e "s/${match}/${match}${insert}/g" native-samples/envoy-config.yaml

    startDockerContainer ${1} ${2}

    for i in {1..20}
    do
      JWT=$($CLI token create -c config.yaml -i $APIKEY -s $APISECRET)
      sleep 30 # skew for JWT
      callTargetWithJWT $JWT
      if [[ $STATUS_CODE -eq 200 ]] ; then
        echo -e "\nServices are ready to be tested"
        break
      fi
    done

    callTargetWithAPIKey $PROD_APIKEY 403
    callTargetWithAPIKey $APIKEY 200

    docker stop adapter && docker stop envoy && docker stop target

    cp native-samples/envoy-config.yaml.bak native-samples/envoy-config.yaml
    match="domains: \"\*\""
    insert="\n              typed_per_filter_config:\n                envoy.filters.http.ext_authz:\n                  \"@type\": type.googleapis.com\/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute\n                  check_settings:\n                    context_extensions:\n                      apigee_environment: test"
    sed -i -e "s/${match}/${match}${insert}/g" native-samples/envoy-config.yaml

    startDockerContainer ${1} ${2}

    for i in {1..20}
    do
      JWT=$($CLI token create -c config.yaml -i $APIKEY -s $APISECRET)
      sleep 30 # skew for JWT
      callTargetWithJWT $JWT
      if [[ $STATUS_CODE -eq 200 ]] ; then
        echo -e "\nServices are ready to be tested"
        break
      fi
    done
    callTargetWithAPIKey $PROD_APIKEY 403
    callTargetWithAPIKey $APIKEY 200

  } || { # exit on failure
    exit 7
  }
}

################################################################################
# Run tests handling environment spec
################################################################################
function runEnvSpecTest {
  chmod 644 ${BUILD_DIR}/configs/*
  sed -i -e "s/{{issuer}}/https:\/\/${ORG}-${ENV}.apigee.net\/remote-token\/token/g" ${BUILD_DIR}/configs/env_spec.yaml
  sed -i -e "s/{{jwks}}/https:\/\/${ORG}-${ENV}.apigee.net\/remote-token\/certs/g" ${BUILD_DIR}/configs/env_spec.yaml

  startDockerContainerForEnvSpec ${1} ${2}

  # make sure quota is restored
  sleep 60

  echo -e "\nGood call: GET /proxy1/get with API key in header"
  callTargetWithAPIKey $APIKEY 200 "" /proxy1/get
  echo -e "\nGood call: GET /proxy1/get with bad key in header"
  callTargetWithAPIKey APIKEY 403 "" /proxy1/get
  echo -e "\nMethod not matched: POST /proxy1/get with API key in header"
  callTargetWithAPIKey $APIKEY 404 "" /proxy1/get POST
  echo -e "\nCredential in wrong place: GET /proxy1/get with API key in query param"
  callTargetWithAPIKeyInQueryParam $APIKEY 401 "" /proxy1/get
  echo -e "\nGood call: GET /proxy1/anything with API key in query param"
  callTargetWithAPIKeyInQueryParam $APIKEY 200 "" /proxy1/anything
  echo -e "\nCredential in wrong place: GET /proxy1/anything with API key in header"
  callTargetWithAPIKey $APIKEY 401 "" /proxy1/anything
  
  echo -e "\nMissing JWT: GET /proxy2/get with API key in header"
  callTargetWithAPIKey $APIKEY 401 "" /proxy2/get
  JWT=$($CLI token create -c config.yaml -i $APIKEY -s $APISECRET)
  sleep 30 # skew for JWT
  echo -e "\nGood call: GET /proxy2/get with JWT in query param"
  callTargetWithJWTInQueryParam $JWT 200 "" /proxy2/get
  echo -e "\nCredential in wrong place: GET /proxy2/get with JWT in the header"
  callTargetWithJWT $JWT 401 "" /proxy2/get
  echo -e "\nGood call: GET /proxy2/checkHeaders with JWT in the header"
  callTargetWithJWT $JWT 200 "" /proxy2/checkHeaders

  echo -e "\nGood call: GET /passthru/get"
  callTargetWithAPIKey "" 200 "" /passthru/get

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
      if [[ $STATUS_CODE -eq 429 ]] ; then
        echo -e "\nQuota depleted"
        break
      fi
      sleep 1
    done
    if [[ $STATUS_CODE -ne 429 ]] ; then
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
      if [[ $STATUS_CODE -eq 429 ]] ; then
        echo -e "\nLocal quota depleted"
        break
      fi
      sleep 1
    done
    if [[ $STATUS_CODE -ne 429 ]] ; then
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
      if [[ $STATUS_CODE -eq 429 ]] ; then
        echo -e "\nQuota for /get depleted"
        break
      fi
      sleep 1
    done
    echo -e "\nTesting quota for /post which should be unaffected..."
    callIstioTargetWithAPIKey $APIKEY 200 httpbin.default.svc.cluster.local /post POST
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
