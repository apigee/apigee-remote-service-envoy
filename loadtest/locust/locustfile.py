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
