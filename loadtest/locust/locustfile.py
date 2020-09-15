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

import random
from locust import HttpUser, task, between, constant
from locust.contrib.fasthttp import FastHttpUser

# https://docs.locust.io/en/stable/writing-a-locustfile.html

# class HttpbinUser(HttpUser):
class HttpbinUser(FastHttpUser):

    # users wait between n1 and n2 seconds after each task
    # wait_time = between(1, 2)
    wait_time = constant(1)

    @task(1000)
    def good_request(self):
      product_id = "product-" + str(random.randint(1, 300))
      headers = {
          'host': product_id,
          'x-api-key': product_id,
      }
      self.client.get("/target", headers=headers)

    # @task(10) # 10 = 1% bad
    # def bad_request(self):
    #   product_id = "product-" + str(random.randint(1001, 2000))
    #   headers = {
    #       'host': product_id,
    #       'x-api-key': 'bad'
    #   }
    #   self.client.get("/target", headers=headers)
