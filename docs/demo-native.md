# Getting Started with SaaS

## Provision the remote-service proxy on Apigee

If you haven't already, follow the [instructions](../../../../apigee-remote-service-cli#apigee-saas) 
to install the CLI and provision the proxy for Apigee Hybrid.

When you've completed provisioning, you will have a `config.yaml` file that will contain 
a Kubernetes ConfigMap definition. We'll use that in the next step.

## Run apigee-remote-service-envoy

You may run either a native binary or on Docker.

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

## Run your Envoy Proxy

There's an example of how to configure Envoy [here](samples/native/envoy-httpbin.yaml).

Edit the file to set your Apigee runtime and cluster information.

When ready, just run:

    envoy -c samples/native/envoy-httpbin.yaml
