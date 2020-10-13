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

  echo -e "\nUpgrading curl..."
  sudo apt remove curl -y
  sudo apt update
  sudo apt install -y libssl-dev autoconf libtool make
  cd /usr/local/src
  sudo rm -rf curl*
  sudo wget https://curl.haxx.se/download/curl-7.72.0.zip
  sudo unzip curl-7.72.0.zip
  cd curl-7.72.0     # enter the directory where curl was unpacked #
  sudo ./buildconf
  sudo ./configure --with-ssl 
  sudo make
  sudo make install
  sudo cp /usr/local/bin/curl /usr/bin/curl
  curl -V

  echo -e "\nUpdating gcloud SDK..."
  gcloud components update --quiet

  echo -e "\nInstalling go 1.15..."
  if [[ -d "/usr/local/go" ]] ; then 
    sudo rm -r /usr/local/go
  fi
  curl -LO https://golang.org/dl/go1.15.2.linux-amd64.tar.gz
  sudo tar -C /usr/local -xzf go1.15.2.linux-amd64.tar.gz
  export PATH=$PATH:/usr/local/go/bin
  sudo chmod 777 /usr/local/go
}

################################################################################
# Build CLI from source code
################################################################################
function buildRemoteServiceCLI {
  echo -e "\nBuilding apigee-remote-service-cli..."
  cd ${KOKORO_ARTIFACTS_DIR}/github/apigee-remote-service-cli
  go mod download
  CGO_ENABLED=0 go build -a -o apigee-remote-service-cli .
}

################################################################################
# Build Adapter Docker Image from source code
################################################################################
function buildAdapterDocker {
  echo -e "\nBuilding local Docker image of apigee-remote-service-envoy..."
  cd ${KOKORO_ARTIFACTS_DIR}/github/apigee-remote-service-envoy
  docker build -t apigee-envoy-adapter:test .
}

installPrerequisites
buildRemoteServiceCLI
buildAdapterDocker