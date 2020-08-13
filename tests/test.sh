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

echo "Fetching the cli binary..."
wget https://github.com/apigee/apigee-remote-service-cli/releases/download/v1.0.0/apigee-remote-service-cli_1.0.0_linux_64-bit.tar.gz
tar -zxvf apigee-remote-service-cli_1.0.0_linux_64-bit.tar.gz apigee-remote-service-cli

export APIGEE_TAG=v1.0.0
export ENVOY_TAG=v1.14.4
export APIGEE_CONFIG=$PWD/config.yaml # this will be generated

echo "Testing Legacy SaaS..."

export USER=$USER
export PASSWORD=$PASSWORD
export ORG=$ORG
export ENV=$ENV
export ENVOY_CONFIG=$PWD/envoy-saas.yaml # bring your own yaml

python3 test_legacy_saas.py

echo "Testing Hybrid..."

echo "Not implemented yet"

echo "Testing OPDK..."

export USER=$USER
export PASSWORD=$PASSWORD
export ORG=$ORG
export ENV=$ENV
export RUNTIME=$RUNTIME
export MGMT=$MGMT
export ENVOY_CONFIG=$PWD/envoy-opdk.yaml # bring your own yaml

python3 test_opdk.py

echo "Not implemented yet"

echo "Cleaning up files..."
rm apigee-remote-service-cli_1.0.0_linux_64-bit.tar.gz
rm config.yaml