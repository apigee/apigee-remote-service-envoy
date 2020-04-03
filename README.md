[![<CirclCI>](https://circleci.com/gh/theganyo/apigee-remote-service-envoy.svg?style=svg)](https://circleci.com/gh/theganyo/apigee-remote-service-envoy)
[![Go Report Card](https://goreportcard.com/badge/github.com/theganyo/apigee-remote-service-envoy)](https://goreportcard.com/report/github.com/theganyo/apigee-remote-service-envoy)
[![codecov.io](https://codecov.io/github/theganyo/apigee-remote-service-envoy/coverage.svg?branch=master)](https://codecov.io/github/theganyo/apigee-remote-service-envoy?branch=master)

# Apigee Remote Service for Envoy

Apigee integration for Envoy.

# Usage

0. Choose your [target](choose-your-target)
1. Install the [remote-service proxy](install-the-remote-service-proxy) on Apigee
2. Configure and run [apigee-remote-service-envoy](run-apigee-remote-service-envoy) 
3. Configure and run [Envoy](run-the-envoy-proxy)


## Choose your target

For standalone, it's often simplest to use an existing service:

* [https://mocktarget.apigee.net/](https://mocktarget.apigee.net/)
* [https://httpbin/](https://httpbin.org/)

Or, to avoid an external network, you can run httpbin in docker:

    docker run docker.io/kennethreitz/httpbin

If you're using Istio, deploy httpbin with a sidecar:

    kubectl label namespace default istio-injection=enabled
    kubectl apply -f samples/httpbin.yaml
    kubectl apply -f samples/httpbin-gateway.yaml

## Install the remote-service proxy

You must provision the remote-service proxy into your Apigee Runtime environment. 
This proxy provides a necessary API for the remote service to access Apigee data. 

Follow the [instructions](../../../apigee-remote-service-cli) to install the CLI and 
provision the proxy for your specific Apigee environment. There are instructions to 
provision in Apigee SaaS, hybrid, or OPDK.

Be sure to save the configuration emitted from your provisioning as `config.yaml`! 
You'll need it to configure the service, as you'll see below.

## Run apigee-remote-service-envoy

* [Native](native)
* [Docker](docker)
* [Kubernetes or Istio](kubernetes-or-istio)

### Native

The Github [releases](../../releases) contains binaries for common platforms.

Just take your `config.yaml` and run:

    apigee-remote-service-envoy -c config.yaml

### Docker

Docker images are published with release tags:

    gcr.io/apigee-api-management-istio/apigee-remote-service-envoy:${VERSION}
    gcr.io/apigee-api-management-istio/apigee-remote-service-envoy-debug:${VERSION}

(See Github [releases](../../releases) for available versions and release notes.)

Run with your local `config.yaml` available as `/config.yaml` via a volume mount:

    docker run -v /local/config.yaml:/config.yaml gcr.io/apigee-api-management-istio/apigee-remote-service-envoy:${VERSION}

### Kubernetes or Istio

#### Namespace

If you don't have your namespace, create it. For example:

    kubectl create namespace apigee

Notes:
* If you use a different namespace, be sure to change DNS references in your configuations.

#### Configuration

When you provisioned, you either generated a simple yaml file or a Kubernetes ConfigMap.
Follow the appropriate step below.

If you generated a ConfigMap, just apply it:

    kubectl apply -f configmap.yaml

If you have a simple YAML file (ie. Kubenernetes attributes), you need to create a ConfigMap
from your YAML file:

    kubectl -n apigee create configmap apigee-remote-service-envoy --from-file=config.yaml

#### Deployment and Service

Now create the `apigee-remote-service-envoy` Deployment and Service: 

    kubectl apply -f samples/istio/saas-apigee-remote-service-envoy.yaml

## Run the Envoy Proxy

Because this service is designed to integrate with a stock 
[Envoy](https://www.envoyproxy.io/) build, there are many options available to you 
for Envoy deployment. Bare Envoy and Istio are described below.

* [Native Envoy](native-envoy)
* [Istio](istio)

## Native Envoy

Just get Envoy and run with configuration! There's an example 
[here](samples/native/envoy-config.yaml). Edit the file to set your target and remote 
service clusters and run.

    envoy-static -c envoy-config.yaml

## Istio 

Apply the EnvoyFilter:

    kubectl apply -f samples/istio/envoyfilter-sidecar.yaml

This filter will apply Apigee controls to all services with Istio sidecare in the 
default namespace.
