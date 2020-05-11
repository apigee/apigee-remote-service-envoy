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

There's an example of how to configure Envoy [here](../samples/native/envoy-httpbin.yaml).

Edit the file to set your Apigee runtime and cluster information.

When ready, just run:

    envoy -c samples/native/envoy-httpbin.yaml

## Configure your Apigee API Product(s)

A sample script you can follow is provided [here](apigee-products.md#sample).
Get your API Key following that process and return here for the next step.

## Use your API Key for authorization

Now that you're authorizated to access your target, let's provide that authentication.
Go back to your `curl` terminal, but this time include the API Key in your request:

    APIKEY=yourkey
    curl -i http://localhost:8080/httpbin/headers -H "x-api-key: $APIKEY"

Bingo! Now you're managing your API with Apigee.

## Next steps

Now you've got the basics, but there's a lot more you can do, including:

* Hit your quota. (Try that curl a few more times.)
* Generate and use JWT tokens.
* Use OAuth scopes with the JWT tokens.
* Access Apigee Analytics (see the `Analyze` menu in the Apigee UI).
* Use the CLI to manage, create tokens, and control bindings.
* Create custom authorization rules against your metadata.
* And more!

But that's for another time.

Enjoy!
