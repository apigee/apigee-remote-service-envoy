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

sudo apt install jq curl -y
gcloud components update --quiet

echo -e "\nInstalling go 1.15..."
if [[ -d "/usr/local/go" ]] ; then sudo rm -r /usr/local/go ; fi
curl -LO https://golang.org/dl/go1.15.2.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.15.2.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
export go_exec="sudo /usr/local/go/bin/go"

${KOKORO_ARTIFACTS_DIR}/github/apigee-remote-service-envoy/kokoro/scripts/integration_test_hybrid.sh