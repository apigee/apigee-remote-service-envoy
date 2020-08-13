# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import os
import requests
import subprocess
from urllib.parse import quote

class ApigeeClient():
  def __init__(self, org, env,
       username="",
       password="",
       token="",
       mgmt_url="",
       runtime_url="",
       cli_dir=""):
    self.org = org
    self.env = env
    self.username = username
    self.password = password
    self.token = token
    self.developer_email = "foo@bar.com"
    self.product_name = "httpbin-product"
    self.app_name = "httpbin-app"
    self.platform = None
    self.runtime_url = runtime_url
    self.revision = "1"
    if mgmt_url != "":
      self.mgmt_url = mgmt_url
      self.platform = "--opdk"
    else:
      if username == "":
        self.mgmt_url = "https://apigee.googleapis.com"
      else:
        self.mgmt_url = "https://api.enterprise.apigee.com"
        self.platform = "--legacy"
    self.cli_dir = cli_dir

  def provision(self, logger):
    cmd = [f"{self.cli_dir}/apigee-remote-service-cli", "provision", "-f",
        "-o", self.org, "-e", self.env]
    if self.platform == None:
      cmd += ["-t", self.token, "-r", self.runtime_url, "-n", "apigee"]
    elif self.platform == "--legacy":
      cmd += [self.platform, "-u", self.username, "-p", self.password]
    elif self.platform == "--opdk":
      cmd += [self.platform, "-r", self.runtime_url, "-m", self.mgmt_url,
          "-u", self.username, "-p", self.password,
          "--virtual-hosts", "default"]
    process = subprocess.run(cmd, capture_output=True)
    if process.stderr != b'':
      logger.error(process.stderr.decode())
    f = open("config.yaml", "wb")
    f.write(process.stdout)
    f.close()

  def fetch_jwt(self, key, secret, logger):
    if self.platform == "--legacy":
      logger.debug(f"fetching JWT from organization {self.org} and environment {self.env}")
      cmd = [f"{self.cli_dir}/apigee-remote-service-cli", "token", "create",
          "--legacy", "-o", self.org, "-e", self.env,
          "-i", key, "-s", secret]
      process = subprocess.run(cmd, capture_output=True)
      if process.stderr != b'':
        logger.error("failed in fetching JWT" + process.stderr.decode())
        return ""
      return process.stdout[:-1].decode() # remove the line breaking
    url = self.runtime_url + "/remote-service/token"
    payload = {
      "client_id": key,
      "client_secret": secret,
      "grant_type": "client_credentials",
    }
    response = requests.post(url=url, json=payload)
    if response.ok == False:
      logger.error("failed in fetching JWT" + response.content.decode())
      return ""
    return json.loads(response.content)["token"]

  def create_apiproduct(self, quota=5):
    product_payload = {
      "name": self.product_name,
      "displayName": "httpbin product",
      "approvalType": "auto",
      "attributes": [
        {
          "name": "access",
          "value": "private",
        },
        {
          "name": "apigee-remote-service-targets",
          "value": "httpbin.org,httpbin.default.svc.cluster.local",
        },
      ],
      "description": "httpbin product for test purpose",
      "apiResources": [
        "/httpbin/headers",
        "/headers",
      ],
      "environments": [
        "test",
      ],
      "quota": str(quota),
      "quotaInterval": "1",
      "quotaTimeUnit": "minute",
    }
    path = f"/v1/organizations/{self.org}/apiproducts"
    return self.post(path, product_payload)

  def create_app(self):
    app_payload = {
      "name" : self.app_name,
      "apiProducts": [
        "httpbin-product",
        "remote-service",
      ]
    }
    path = f"/v1/organizations/{self.org}/developers/{self.developer_email}/apps"
    return self.post(path, app_payload)

  def fetch_credentials(self):
    response = self.get_app()
    if response.status_code != 200:
      return "", ""
    body = json.loads(response.content)
    key = body["credentials"][0]["consumerKey"]
    secret = body["credentials"][0]["consumerSecret"]
    return key, secret

  def create_developer(self):
    developer_payload = {
      "email": self.developer_email,
      "firstName": "Foo",
      "lastName": "Bar",
      "userName": "foobar"
    }
    path =  f"/v1/organizations/{self.org}/developers"
    return self.post(path, developer_payload)

  def get_app(self):
    path = f"/v1/organizations/{self.org}" + \
      f"/developers/{self.developer_email}/apps/{self.app_name}"
    return self.get(path)

  def get_deployments(self):
    path = f"/v1/organizations/{self.org}/environments/{self.env}" + \
      "/apis/remote-service/deployments"
    return self.get(path)

  # undeploy remote-service proxies
  def undeploy_proxy(self):
    response = self.get_deployments()
    if response.status_code != 200:
      raise Exception("unable to get deployments of remote-service proxies")
    body = json.loads(response.content)
    if self.platform != None:
      self.revision = body['revision'][0]['name']
    else:
      self.revision = body['deployments'][0]['revision']
    path = f"/v1/organizations/{self.org}/environments/{self.env}" + \
      f"/apis/remote-service/revisions/{self.revision}/deployments"
    return self.delete(path)
    
  def deploy_proxy(self):
    path = f"/v1/organizations/{self.org}/environments/{self.env}" + \
      f"/apis/remote-service/revisions/{self.revision}/deployments"
    return self.post(path, None)

  def delete_developer(self):
    path = f"/v1/organizations/{self.org}/developers/{self.developer_email}"
    return self.delete(path)

  def delete_product(self, name=None):
    if name is None:
      name = self.product_name
    path = f"/v1/organizations/{self.org}/apiproducts/{name}"
    return self.delete(path)

  def delete_proxies(self):
    path = f"/v1/organizations/{self.org}/apis/remote-service"
    return self.delete(path)

  def post(self, path, payload):
    url = self.mgmt_url + quote(path)
    if self.token != "":
      auth_header = {"Authorization": f"Bearer {self.token}"}
      return requests.post(url=url, headers=auth_header, json=payload)
    return requests.post(url=url,
              auth=(self.username, self.password),
              json=payload)

  def get(self, path):
    url = self.mgmt_url + quote(path)
    if self.token != "":
      auth_header = {"Authorization": f"Bearer {self.token}"}
      return requests.get(url=url, headers=auth_header)
    return requests.get(url=url, auth=(self.username, self.password))

  def delete(self, path):
    url = self.mgmt_url + quote(path)
    if self.token != "":
      auth_header = {"Authorization": f"Bearer {self.token}"}
      return requests.delete(url=url, headers=auth_header)
    return requests.delete(url=url, auth=(self.username, self.password))



