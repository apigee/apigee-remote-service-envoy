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
import utils
import test_client
import time

def deploy(logger):
  deployment.KubeManager.apply("config.yaml", logger)

  hybrid_configs = os.getenv("HYBRID_CONFIGS", "hybrid-configs")
  deployment.KubeManager.apply(hybrid_configs, logger)
  time.sleep(20)

  hybrid_deployments = os.getenv("HYBRID_DEPLOYMENTS", "hybrid-deployments")
  deployment.KubeManager.apply(hybrid_deployments, logger)

def main():
  logger = utils.get_logger("Hybrid Test")

  apigee_client = apigee.ApigeeClient(org=os.getenv("ORG"), env=os.getenv("ENV"),
    token=os.getenv("TOKEN"), runtime_url=os.getenv("RUNTIME"),
    cli_dir=os.getenv("CLI_DIR", "."))

  utils.provision(logger, apigee_client)

  deploy(logger)

  logger.debug("waiting for pods to get ready. this takes about four minutes...")
  time.sleep(240)

  utils.start_hybrid_test(logger, apigee_client)

  utils.cleanup(logger, apigee_client)

  deployment.KubeManager.delete("apigee-remote-service-envoy", "apigee", logger)
  deployment.KubeManager.delete("curl", "default", logger, "pods")
  deployment.KubeManager.delete("httpbin", "default", logger)

if __name__ == "__main__":
  main()