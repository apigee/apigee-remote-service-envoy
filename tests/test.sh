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

set -e

export APIGEE_VERSION=1.1.0-rc.1
export APIGEE_TAG=v${APIGEE_VERSION}
export ENVOY_TAG=v1.15.0
export ISTIO_VERSION=istio-1.6

echo "Fetching the cli binary..."
wget https://github.com/apigee/apigee-remote-service-cli/releases/download/${APIGEE_TAG}/apigee-remote-service-cli_1.1.0-rc.1_linux_64-bit.tar.gz
tar -zxvf apigee-remote-service-cli_${APIGEE_VERSION}_linux_64-bit.tar.gz apigee-remote-service-cli
rm apigee-remote-service-cli_${APIGEE_VERSION}_linux_64-bit.tar.gz

export APIGEE_CONFIG=$PWD/config.yaml # this will be generated

echo "Testing Legacy SaaS..."

export USER=$USER
export PASSWORD=$PASSWORD
export ORG=$ORG
export ENV=$ENV
export K8S_CONTEXT=$K8S_CONTEXT

python3 test_legacy_saas.py

echo "Cleaning up files..."
rm config.yaml

echo "Testing Hybrid..."

export ORG=$ORG
export ENV=$ENV
export RUNTIME=$RUNTIME
export TOKEN=$(gcloud auth print-access-token)
export K8S_CONTEXT=$K8S_CONTEXT

python3 test_hybrid.py

echo "Cleaning up files..."
rm config.yaml

echo "Testing OPDK..."

export USER=$USER
export PASSWORD=$PASSWORD
export ORG=$ORG
export ENV=$ENV
export RUNTIME=$RUNTIME
export MGMT=$MGMT
export K8S_CONTEXT=$K8S_CONTEXT

python3 test_opdk.py

echo "Cleaning up files..."
rm config.yaml