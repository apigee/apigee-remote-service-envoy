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

import deployment
import os
import requests
import subprocess
import time

class LocalTestClient():
  """
  LocalTestClient assumes the Envoy proxy listenning locally on localhost:8080
  It needs a valid ApigeeClient to fetch the necessary credentials
  """
  def __init__(self, apigee_client):
    self.apigee_client = apigee_client
    self.key, self.secret = apigee_client.fetch_credentials()
    self.url = "http://localhost:8080/headers"

  def test_apikey(self, logger, expect=200):
    apikey_header = {"x-api-key": self.key}
    response = requests.get(url=self.url, headers=apikey_header)
    status = response.status_code
    if expect == None:
      logger.debug(f"call using API key got response code {status}")
      return status
    if status != expect:
      logger.error(f"failed to test target service using API key in headers, expected {expect} got {status}")
    else:
      logger.debug(f"call using API key got response code {status} as expected")
    return status

  def test_invalid_apikey(self, logger, expect=403):
    apikey_header = {"x-api-key": "key"}
    response = requests.get(url=self.url, headers=apikey_header)
    status = response.status_code
    if status != expect:
      logger.error(f"failed to test target service using invalid API key in headers, expected {expect} got {status}")
    else:
      logger.debug(f"call using invalid API key got response code {status} as expected")
    return status

  def test_apikey_params(self, logger, expect=200):
    url = f"{self.url}?x-api-key={self.key}"
    response = requests.get(url=url)
    status = response.status_code
    if expect == None:
      logger.debug(f"call using API key got response code {status}")
      return status
    if status != expect:
      logger.error(f"failed to test target service using API key in params, expected {expect} got {status}")
    else:
      logger.debug(f"call using API key got response code {status} as expected")
    return status

  def test_jwt(self, cli_dir, logger, expect=200):
    token = self.apigee_client.fetch_jwt(self.key, self.secret, logger)
    auth_header = {"Authorization": f"Bearer {token}"}
    response = requests.get(url=self.url, headers=auth_header)
    status = response.status_code
    if expect == None:
      logger.debug(f"call using JWT got response code {status}")
      return status
    if status != expect:
      logger.error(f"failed to test target service using JWT, expected {expect} got {status}")
    else:
      logger.debug(f"call using JWT got response code {status} as expected")
    return status

  def test_invalid_jwt(self, logger, expect=401):
    auth_header = {"Authorization": "Bearer token"}
    response = requests.get(url=self.url, headers=auth_header)
    status = response.status_code
    if status != expect:
      logger.error(f"failed to test target service using invalid JWT, expected {expect} got {status}")
    else:
      logger.debug(f"call using invalid JWT got response code {status} as expected")
    return status

  def test_quota(self, quota, logger):
    for _ in range(quota + 10):
      if self.test_apikey(logger, None) != 200:
        logger.debug("quota depleted")
        break

    time.sleep(1)

    logger.debug("expecting this call to fail for quota depletion...")
    self.test_apikey(logger, 403)

    logger.debug("waiting for quota to be restored. this takes about a minute...")
    time.sleep(65)

    logger.debug("expecting this call to succeed with restored quota...")
    self.test_apikey(logger, 200)

  def test_local_quota(self, quota, logger):
    # turn the remote-service proxies offline
    logger.debug("turning the remote-service proxies offline...")
    try:
      response = self.apigee_client.undeploy_proxy()
      if response.ok == False:
        logger.error("turning the remote-service proxies offline")
        logger.error(response.content.decode())
    except Exception as e:
      logger.error(e)

    time.sleep(5)

    logger.debug("performing local quota test...")
    self.test_quota(quota, logger)

    # turn the remote-service proxies back on
    logger.debug("turning the remote-service proxies back on...")
    response = self.apigee_client.deploy_proxy()
    if response.ok == False:
      logger.error("turning the remote-service proxies back on")
      logger.error(response.content.decode())

class IstioTestClient():
  """
  IstioTestClient assumes the Envoy proxy listenning locally on localhost:8080
  It needs a valid ApigeeClient to fetch the necessary credentials
  """
  def __init__(self, apigee_client, logger):
    self.apigee_client = apigee_client
    self.key, self.secret = apigee_client.fetch_credentials()

  def curl(self, header, logger):
    cmd = "kubectl exec curl -c curl -- curl -iv httpbin.default.svc.cluster.local/headers -H"
    process = subprocess.run(cmd.split(" ") + [header], capture_output=True)
    try:
      status = int(process.stdout.decode().splitlines()[0].split(" ")[1])
      return status
    except:
      logger.error(process.stderr.decode())
      logger.error(process.stdout.decode())
      return 500

  def test_apikey(self, logger, expect=200):
    apikey_header = f"x-api-key: {self.key}"
    status = self.curl(apikey_header, logger)
    if expect == None:
      logger.debug(f"call using API key got response code {status}")
      return status
    if status != expect:
      logger.error(f"failed to test target service using API key, expected {expect} got {status}")
    else:    
      logger.debug(f"call using API key got response code {status} as expected")
    return status

  def test_invalid_apikey(self, logger, expect=403):
    apikey_header = "x-api-key: key"
    status = self.curl(apikey_header, logger)
    if status != expect:
      logger.error(f"failed to test target service using invalid API key in headers, expected {expect} got {status}")
    else:
      logger.debug(f"call using invalid API key got response code {status} as expected")
    return status

  def test_jwt(self, cli_dir, logger, expect=200):
    token = self.apigee_client.fetch_jwt(self.key, self.secret, logger)
    auth_header = f"Authorization: Bearer {token}"
    status = self.curl(auth_header, logger)
    if expect == None:
      logger.debug(f"call using JWT got response code {status}")
      return status
    if status != expect:
      logger.error(f"failed to test target service using JWT, expected {expect} got {status}")
    else:
      logger.debug(f"call using JWT got response code {status} as expected")
    return status

  def test_invalid_jwt(self, logger, expect=401):
    auth_header = "Authorization: Bearer token"
    status = self.curl(auth_header, logger)
    if status != expect:
      logger.error(f"failed to test target service using invalid JWT, expected {expect} got {status}")
    else:
      logger.debug(f"call using invalid JWT got response code {status} as expected")
    return status

  def test_quota(self, quota, logger, cli_dir="."):
    for _ in range(quota + 10):
      if self.test_apikey(logger, None) != 200:
        logger.debug("quota depleted")
        break

    time.sleep(1)

    logger.debug("expecting this call to fail for quota depletion...")
    self.test_apikey(logger, 403)

    logger.debug("waiting for quota to be restored. this takes about a minute...")
    time.sleep(65)

    logger.debug("expecting this call to succeed with restored quota...")
    self.test_apikey(logger, 200)

  def test_local_quota(self, quota, logger, cli_dir="."):
    # turn the remote-service proxies offline
    logger.debug("turning the remote-service proxies offline...")
    try:
      response = self.apigee_client.undeploy_proxy()
      if response.ok == False:
        logger.error("turning the remote-service proxies offline")
        logger.error(response.content.decode())
    except Exception as e:
      logger.error(e)

    time.sleep(30)

    logger.debug("performing local quota test...")
    self.test_quota(quota, logger, cli_dir)

    # turn the remote-service proxies back on
    logger.debug("turning the remote-service proxies back on...")
    response = self.apigee_client.deploy_proxy()
    if response.ok == False:
      logger.error("turning the remote-service proxies back on")
      logger.error(response.content.decode())