#!/bin/bash

set -e

echo "Fetching the cli binary..."
wget https://github.com/apigee/apigee-remote-service-cli/releases/download/v1.0.0/apigee-remote-service-cli_1.0.0_linux_64-bit.tar.gz
tar -zxvf apigee-remote-service-cli_1.0.0_linux_64-bit.tar.gz apigee-remote-service-cli

echo "Testing Legacy SaaS..."

# set up necessary environment variables read by the python script
USER=$USER
PASSWORD=$PASSWORD
ORG=$ORG
ENV=$ENV
APIGEE_TAG=v1.0.0
ENVOY_TAG=v1.14.4
APIGEE_CONFIG=$PWD/config.yaml # this will be generated
ENVOY_CONFIG=$PWD/envoy-httpbin.yaml # bring your own yaml

python3 test_legacy_saas.py

echo "Testing Hybrid..."

echo "Not implemented yet"

echo "Testing OPDK..."

echo "Not implemented yet"

echo "Cleaning up files..."
rm apigee-remote-service-cli_1.0.0_linux_64-bit.tar.gz
rm config.yaml