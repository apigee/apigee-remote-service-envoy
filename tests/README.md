# Test Workflows for Apigee Envoy Adapter

## Overview

The workflow consists of a number of python scripts executed in the `test.sh` shell script. The shell script sets and exports the necessary environment variables which python processes will read, downloads the `apigee-remote-service-cli` binary and cleans it up as well as intermediate files.

## What it does

The three main test scripts are `test_legacy_saas.py`, `test_hybrid.py` and `test_opdk.py`. None of the scripts provisions the Apigee orgnanization or Apigee runtime cluster. Instead, they expect valid credentials and configuration files for existing Apigee environment to provision and deploy
  * `remote-service` proxy bundles,
  * `remote-service` and `httpbin product` API products,
  * a developer with email `foo@bar.com`,
  * `httpbin app` Application associated with the developer and authorized to use the above two products.

The script will not attempt to override any exisiting resources if conflict ever occurs. Likewise, existing dependencies might prevent from the aforementioned resources being deleted.

As of now, calls using API keys (either in http headers or query parameters), JWT and (local) quota deletion and restoration are being tested on all three platforms. As an API product for the target service, a quota (5 calls per minute by default) is set for `httpbin product`.

The default python logging library is used. In addition to the default setting, the logger is configured to stream the ouput to stderr for the convenience of local testing purpose.

## Running tests locally

Have your Apigee organization (as well as runtime cluster for hybrid) ready. If you do not intend to test all platforms, simply comment out the the other python script executions. For any Istio environment, please enable Istio sidecar injection for the `default` namespace.

Assign proper values to the environment variables in `test.sh`. While all variables are straightforward to understand, the `$K8S_CONTEXT` should be the full name of the context that one can run `kubetcl config use-context ...` with. It is the Kubernetes cluster with Istio (and Hybrid runtime if applicable) installed for each platform.

Run `./test.sh` and watch the output!

## To-do

- Testing more cli commands, in particular those interacting with the `remote-service` proxies or Apigee management plane such as `bindings ...` and `token rotate-cert ...`. 

- Establishing performance test potentially utilizing the locust python library.

## Possible changes

- When running in a automated fashion, all the environment variables will be looked up in some data store such that a different `test.sh` which does not tamper with the environment variables is needed.

- The current plan for automated tests is the instance will be assigned a service account to fetch necessary credentials from the GCP project. If this changes, we will need to find a different way to solve the permission issue.
