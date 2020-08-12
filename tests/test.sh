#!/bin/bash

set -e

wget https://github.com/apigee/apigee-remote-service-cli/releases/download/v1.0.0/apigee-remote-service-cli_1.0.0_linux_64-bit.tar.gz
tar -zxvf apigee-remote-service-cli_1.0.0_linux_64-bit.tar.gz apigee-remote-service-cli
export USER=$USER
export PASSWORD=$PASSWORD
export ORG=lwge-eval
export ENV=test
APIGEE_TAG=v1.0.0
ENVOY_TAG=v1.14.4
APIGEE_CONFIG=$PWD/config.yaml
ENVOY_CONFIG=$PWD/envoy-httpbin.yaml

echo "Testing Legacy SaaS..."
python3 test_legacy_saas.py

echo "Testing Hybrid..."
echo "Not implemented yet"

echo "Testing OPDK..."
echo "Not implemented yet"

echo "Cleaning up..."
rm apigee-remote-service-cli_1.0.0_linux_64-bit.tar.gz
rm config.yaml