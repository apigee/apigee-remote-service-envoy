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

import apigee_client as apigee
import deployment
import os
import json
import subprocess
import test_client
import time
import utils

def deploy(logger):
  istio_version = os.getenv("ISTIO_VERSION", "istio-1.6")
  cmd = [os.getenv("CLI_DIR", ".")+"/apigee-remote-service-cli", "samples", "create",
          "-c", "config.yaml", "--out", "hybrid-configs", "-t", istio_version, "-f"]
  process = subprocess.run(cmd, capture_output=True)
  if process.stderr != b'':
    logger.error(process.stderr.decode())

  deployment.KubeManager.apply("config.yaml", logger)
  deployment.KubeManager.apply("curl.yml", logger)

  time.sleep(10)

  deployment.KubeManager.apply("hybrid-configs", logger)

def main():
  logger = utils.get_logger("Hybrid Test")

  apigee_client = apigee.ApigeeClient(org=os.getenv("ORG"), env=os.getenv("ENV"),
    token=os.getenv("TOKEN"), runtime_url=os.getenv("RUNTIME"),
    cli_dir=os.getenv("CLI_DIR", "."))

  utils.provision(logger, apigee_client)

  cmd = ["kubectl", "config", "use-context", os.getenv("K8S_CONTEXT")]
  process = subprocess.run(cmd, capture_output=True)
  if process.stderr != b'':
    logger.error(process.stderr.decode())
  logger.debug(process.stdout.decode())

  deploy(logger)

  utils.start_istio_test(logger, apigee_client)

  utils.cleanup(logger, apigee_client)

  deployment.KubeManager.delete("apigee-remote-service-envoy", "apigee", logger)
  deployment.KubeManager.delete("apigee-remote-service-envoy", "apigee", logger, "services")
  deployment.KubeManager.delete("curl", "default", logger, "pods")
  deployment.KubeManager.delete("httpbin", "default", logger)
  deployment.KubeManager.delete("httpbin", "default", logger, "services")
  deployment.KubeManager.delete("apigee", "default", logger, "requestauthentications.security.istio.io")
  deployment.KubeManager.delete("apigee-remote-httpbin", "default", logger, "envoyfilters.networking.istio.io")


if __name__ == "__main__":
  main()