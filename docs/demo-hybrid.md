# Getting Started with Hybrid

## Provision the remote-service proxy on Apigee

If you haven't already, follow the [instructions](../../../../apigee-remote-service-cli#apigee-hybrid) 
to install the CLI and provision the proxy for Apigee Hybrid.

## Deploy a target in Istio

We'll install httpbin as a sample in the default namespace:

    kubectl label namespace default istio-injection=enabled
    kubectl apply -f samples/istio/httpbin.yaml

Now let's start a curl client inside the mesh and make a call to it:

    kubernetes run -it curl --image=curlimages/curl --restart=Never -- sh
    curl -i httpbin.default.svc.cluster.local/headers

Keep your curl client running. We'll use it again later.

## Run Apigee Remote Service for Envoy in your mesh

Now that we have the Runtime API set up, we need to start the Apigee Remote Service
for Envoy in your mesh. This service will provide the endpoints to the Istio sidecars
that are installed on your target services (like httpbin).

#### Configuration

Apply your ConfigMap file to Kubernetes. This provides necessary configuration for
the Apigee Remote Service to access the Runtime API.

    kubectl apply -f config.yaml

#### Deployment

Next, we'll deploy the Apigee Remote Service to your cluster. This will provide the 
necessary endpoints to the Envoy sidecars managed by Istio to protect your target
services (like httpbin).

Before we can do that, however, you'll need to make a couple of changes to the sample file.

Edit `samples/istio/hybrid-apigee-remote-service-envoy.yaml` and make the following
changes:

1. Set the `image:` to reference proper $RELEASE tag (see [releases](../../releases).

    image: "gcr.io/theganyo-playground/apigee-remote-service-envoy:$RELEASE"

2. Set the `secretName` in `tls-volume` to your organization and environment.

      - name: tls-volume
        secret:
          defaultMode: 420
          secretName: apigee-runtime-$ORG-$ENV-tls

With that done, we can deploy the `apigee-remote-service` to your mesh:

    kubectl apply -f samples/istio/hybrid-apigee-remote-service-envoy.yaml

## Configure the Istio sidecar

With that setup complete, we're ready to configure Istio to protect your target!
All we need to do is apply an EnvoyFilter for Istio to discover:

    kubectl apply -f samples/istio/envoyfilter-sidecar.yaml

This filter will apply Apigee management to all services in the default namespace
that have the `managed-by: apigee` label--as our `httpbin` example does.

Once applied, you should get an authorization error when calling your `httpbin` target.
Go back to the Kubernetes `curl` client we started and try it:

    curl -i httpbin.default.svc.cluster.local/headers

Your target is now managed by Apigee!

## Configure an Apigee API Product

Policy is defined in Apigee API Products and enforced by the Apigee Remote Service.
We need to create an API Product to define that policy.

Log into your [Apigee UI](https://apigee.google.com/).

Click on `API Products` then click the blue `+ API Product` button.

* In the `Product Details` section, set the name to `httpbin`.
* Select your environment(s).
* Set `Access` to `Private`.
* Set the `Quota` to `5` requests every `1` `minute`.
* Add a `Path` with the `+Custom Resource` button. Set the path to `/`.
* Create a `Custom attribute` with key: `apigee-remote-service-targets` and value: `httpbin.default.svc.cluster.local`.
* Click the blue `Save` button.

(Note that the value we used in the attributes is the simply the fully qualified DNS name 
of the httpbin service we created in Kubernetes.)

Now, we'll create a Developer to grant access to:

* Click on `Developers` in the left menu and click the blue `+ Developer` button.
* Use whatever values you wish. Be creative.
* Save the Developer.

Finally, let's create an App for that Developer that will have access to our API Product:

* Click on `Apps` in the left menu and click the blue `+ App` button.
* In the `App Details` section, set the name to `httpbin`.
* Select the `Developer` you created above.
* In the `Credentials` section, click the blue `Add Product` button.
* Choose the `httpbin` product and click the blue `Add` button.
* Click the blue `Create` button.

The Credentials status now should say `Approved`. By creating an App, we've created a set 
of Credentials associated with the API Products! These credentials will grant us access 
to the targets of the API Products.

* Click the `Show` button next to the `Key`. That's your App's API Key.
* You can use this key in Apigee managed requests for authorization. Save the key.

## Use your API Key for authorization

Now that you're authorizated to access your target, let's provide that authentication.
Go back to your `curl` terminal, but this time include the API Key in your request:

    APIKEY=yourkey
    curl -i httpbin.default.svc.cluster.local/headers -H "x-api-key: $APIKEY"

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
