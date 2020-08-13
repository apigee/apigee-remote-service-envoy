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

import os
import subprocess

class LegacyManager():
  @staticmethod
  def start_envoy(config_file, tag, log_level="debug"):
    cmd = ["docker", "run", "-v", f"{config_file}:/envoy.yaml",
        "--name=envoy", "--network=host", "--rm", "-d",
        f"envoyproxy/envoy:{tag}", "-c", "/envoy.yaml",
        "-l", log_level
    ]
    process = subprocess.run(cmd, capture_output=True)
    if process.stderr == b'':
      return process.stdout.decode()
    raise Exception("starting Envoy container" + process.stderr.decode())

  @staticmethod
  def start_adapter(config_file, tag, log_level="DEBUG"):
    cmd = ["docker", "run", "-v", f"{config_file}:/config.yaml",
        "--name=adapter", "--rm", "-d",
        "-p", "5000:5000", "-p", "5001:5001",
        f"google/apigee-envoy-adapter:{tag}", "-c", "/config.yaml",
        "-l", log_level
    ]
    process = subprocess.run(cmd, capture_output=True)
    if process.stderr == b'':
      return process.stdout.decode()
    raise Exception("starting Apigee Adapter container" + process.stderr.decode())

  @staticmethod
  def stop_adapter():
    cmd = ["docker", "stop", "adapter"]
    process = subprocess.run(cmd, capture_output=True)
    if process.stderr == b'':
      return process.stdout.decode()
    raise Exception("stopping Apigee Adapter container" + process.stderr.decode())

  @staticmethod
  def stop_envoy():
    cmd = ["docker", "stop", "envoy"]
    process = subprocess.run(cmd, capture_output=True)
    if process.stderr == b'':
      return process.stdout.decode()
    raise Exception("stopping Envoy container" + process.stderr.decode())

class KubeManager():
  @staticmethod
  def apply(file, logger):
    cmd = ["kubectl", "apply", "-f", file]
    logger.debug("executing " + " ".join(cmd))
    process = subprocess.run(cmd, capture_output=True)
    logger.debug(process.stdout.decode())
    if process.stderr != b'':
      logger.error("applying kubectl command: " + process.stderr.decode())

  @staticmethod
  def delete(name, namespace, logger, type="deployment"):
    cmd = ["kubectl", "delete", type, name, "-n", namespace]
    logger.debug("executing " + " ".join(cmd))
    process = subprocess.run(cmd, capture_output=True)
    logger.debug(process.stdout.decode())
    if process.stderr != b'':
      logger.error("applying kubectl command: " + process.stderr.decode())
  