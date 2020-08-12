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
import logging
import sys
import test_client
import time

def get_logger(name):
  logger = logging.getLogger(name)
  logger.setLevel(logging.DEBUG)
  handler = logging.StreamHandler(sys.stdout)
  handler.setLevel(logging.DEBUG)
  formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
  handler.setFormatter(formatter)
  logger.addHandler(handler)
  return logger

def provision(logger, apigee_client):
  logger.debug("creating Apigee client")

  logger.debug("provisioning with cli")
  apigee_client.provision(os.getenv("CLI_DIR", "."), logger)

  logger.debug("creating target API product")
  response = apigee_client.create_apiproduct()
  if response.ok == False:
    logger.error("creating target API product")
    logger.error(response.content.decode())

  logger.debug("creating App developer")
  response = apigee_client.create_developer()
  if response.ok == False:
    logger.error("creating App developer")
    logger.error(response.content.decode())

  logger.debug("creating App")
  response = apigee_client.create_app()
  if response.ok == False:
    logger.error("creating App")
    logger.error(response.content.decode())

def start_containers(logger):
  pwd = os.getenv("PWD")
  adapter_tag = os.getenv("APIGEE_TAG", "v1.0.0")
  logger.debug("Apigee Adapter version tag: " + adapter_tag)

  adapter_config = os.getenv("APIGEE_CONFIG", f"{pwd}/config.yaml")
  logger.debug("Apigee Adapter config file: " + adapter_config)

  envoy_tag = os.getenv("ENVOY_TAG", "v1.14.4")
  logger.debug("Envoy version tag: " + envoy_tag)

  envoy_config = os.getenv("ENVOY_CONFIG", f"{pwd}/envoy-httpbin.yaml")
  logger.debug("Envoy config file: " + envoy_config)

  logger.debug("starting Apigee adapter docker container")
  try:
    output = deployment.LegacyManager.start_adapter(adapter_config, adapter_tag)
    logger.debug(output)
  except Exception as e:
    logger.error(e)

  logger.debug("starting Envoy docker container")
  try:
    output = deployment.LegacyManager.start_envoy(envoy_config, envoy_tag)
    logger.debug(output)
  except Exception as e:
    logger.error(e)

def start_test(logger, apigee_client):
  client = test_client.LegacyTestClient(apigee_client)

  try:
    logger.debug("testing calls to target service with API key")
    client.test_apikey(logger)
  except Exception as e:
    logger.error(e)

  try:
    logger.debug("testing calls to target service with JWT")
    client.test_jwt(os.getenv("CLI_DIR", "."), logger)
  except Exception as e:
    logger.error(e)

  try:
    logger.debug("testing API product quota")
    client.test_quota(5, logger)
  except Exception as e:
    logger.error(e)

  try:
    logger.debug("testing local API product quota")
    client.test_local_quota(5, logger)
  except Exception as e:
    logger.error(e)

def stop_containers(logger):
  logger.debug("stoping Apigee adapter docker container")
  try:
    output = deployment.LegacyManager.stop_adapter()
    logger.debug(output)
  except Exception as e:
    logger.error(e)

  logger.debug("stoping Envoy docker container")
  try:
    output = deployment.LegacyManager.stop_envoy()
    logger.debug(output)
  except Exception as e:
    logger.error(e)

def cleanup(logger, apigee_client):
  stop_containers(logger)

  logger.debug("deleting App developer...")
  response = apigee_client.delete_developer()
  if response.ok == False:
    logger.error("deleting App developer")
    logger.error(response.content.decode())

  logger.debug("deleting target service API product...")
  response = apigee_client.delete_product()
  if response.ok == False:
    logger.error("deleting target service API product")
    logger.error(response.content.decode())

  logger.debug("deleting remote-service API product...")
  response = apigee_client.delete_product("remote-service")
  if response.ok == False:
    logger.error("deleting remote-service API product")
    logger.error(response.content.decode())

  logger.debug("deleting remote-service API proxies...")
  try:
    apigee_client.undeploy_proxy()
  except Exception as e:
    logger.error(e)
  response = apigee_client.delete_proxies()
  if response.ok == False:
    logger.error("deleting remote-service API proxies")
    logger.error(response.content.decode())

if __name__ == '__main__':
  logger = get_logger("Legacy SaaS Test")

  apigee_client = apigee.ApigeeClient(org=os.getenv("ORG"), env=os.getenv("ENV"),
    username=os.getenv("USER"), password=os.getenv("PASSWORD"))

  provision(logger, apigee_client)

  start_containers(logger)

  logger.debug("waiting for adapter to fetch the latest product info. this takes about two minutes...")
  time.sleep(120)

  start_test(logger, apigee_client)

  cleanup(logger, apigee_client)