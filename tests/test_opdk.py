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

def main():
  logger = utils.get_logger("OPDK Test")

  apigee_client = apigee.ApigeeClient(org=os.getenv("ORG"), env=os.getenv("ENV"),
    username=os.getenv("USER"), password=os.getenv("PASSWORD"),
    mgmt_url=os.getenv("MGMT"), runtime_url=os.getenv("RUNTIME"),
    cli_dir=os.getenv("CLI_DIR", "."))

  utils.provision(logger, apigee_client)

  utils.start_containers(logger)

  logger.debug("waiting for adapter to fetch the latest product info. this takes about two minutes...")
  time.sleep(120)

  utils.start_local_test(logger, apigee_client)

  utils.stop_containers(logger)

  utils.cleanup(logger, apigee_client)

if __name__ == "__main__":
  main()