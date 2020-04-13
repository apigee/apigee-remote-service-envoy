#!/bin/bash

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

# This script will install gcloud on the local machine. Not recommended for use
# on development machines, it is mainly used for containers in CI.

if [[ `command -v gcloud` != "" ]]; then
  echo "gcloud already installed."
  exit 0
fi

echo "Installing gcloud..."
wget -O /tmp/gcloud.tar.gz https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-sdk-234.0.0-linux-x86_64.tar.gz || exit 1
sudo tar -zx -C /opt -f /tmp/gcloud.tar.gz

# Need to ln so that `sudo gcloud` works
sudo ln -s /opt/google-cloud-sdk/bin/gcloud /usr/bin/gcloud
