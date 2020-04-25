# Getting Started with Hybrid

## Deploy a target service in Istio

We'll just install httpbin as a sample in the default namespace:

    kubectl label namespace default istio-injection=enabled
    kubectl apply -f samples/httpbin.yaml
    kubectl apply -f samples/httpbin-gateway.yaml

You should be able to reach this target using your Hybrid virtualhost hostAlias:

    hybridHostAlias=my.hybrid.domain.com
    curl -i http://$hybridHostAlias/httpbin/headers

(Note that we're using `http` intead of `https` just to avoid any conflicts.)

## Install the remote-service proxy

Provision the `remote-service` proxy into your Apigee Runtime environment. 
This proxy provides a necessary API for the remote service to access Apigee data. 

Follow the [instructions](../../../../apigee-remote-service-cli#apigee-hybrid) to install the CLI and 
provision the proxy for Apigee Hybrid.

## Run apigee-remote-service-envoy

#### ConfigMap

Apply your ConfigMap file to Kubernetes. This will be accessed by the 
`apigee-remote-service-envoy` deployment.

    kubectl apply -f config.yaml

#### Deployment

Now we'll deploy the `apigee-remote-service-envoy` service. Before we can do that,
however, you'll need to make a couple of changes to the sample file.

Open `samples/istio/hybrid-apigee-remote-service-envoy.yaml` and make the follow
edits:

1. Set the `image:` to reference proper $RELEASE tag (see [releases](../../releases).

    image: "gcr.io/theganyo-playground/apigee-remote-service-envoy:$RELEASE"

2. Set the `secretName` in `tls-volume` to your organization and environment.

      - name: tls-volume
        secret:
          defaultMode: 420
          secretName: apigee-runtime-$ORG-$ENV-tls

3. Deploy the remote service to Kubernetes:

    kubectl apply -f samples/istio/hybrid-apigee-remote-service-envoy.yaml

## Configure the Istio sidecar

Apply the EnvoyFilter:

    kubectl apply -f samples/istio/envoyfilter-sidecar.yaml

This filter will apply Apigee authorization to all services in the default namespace.
At this point, you should get an authorization error when calling your httpbin target.

    curl -i http://$hybridHostAlias/httpbin/headers

## Configure an Apigee API Product

Policy is defined in Apigee API Products and enforced by the Apigee Remote Service.
We'll create an API Product, Developer, and App that will control access.

1. Log into your [Apigee UI](https://apigee.google.com/).

2. Click on `API Products` then click the blue `+ API Product` button.

* In the `Product Details` section, set the name to `httpbin`.
* Select your environment(s).
* Set `Access` to `Private`.
* Set the `Quota` to `5` requests every `1` `minute`.
* Add a `Path` with the `+Custom Resource` button. Set the path to `/`.
* Create a `Custom attribute` with key: `apigee-remote-service-targets` and value: `httpbin.default.svc.cluster.local`.
* Click the blue `Save` button.

Note: You can also use the `apigee-remote-sevice-cli` command to set service targets. Note that the value we used
is the just the DNS name of the httpbin service we created in Kubernetes.

1. Create a Developer. 
 
* Click on `Developers` in the left menu and click the blue `+ Developer` button.
* Use whatever values you wish. Be creative.
* Save the Developer.

2. Create an App.

* Click on `Apps` in the left menu and click the blue `+ App` button.
* In the `App Details` section, set the name to `httpbin`.
* Select the `Developer` you created above.
* In the `Credentials` section, click the blue `Add Product` button.
* Choose the `httpbin` product and click the blue `Add` button.
* Click the blue `Create` button.

3. Obtain Credentials

By creating an App, you've created a set of credentials that grant the `Developer` you created 
access to your `API Product`. Note: The Credentials status should say `Approved`.

* Click the `Show` button next to the `Key`. That's your API Key.
* Your App will use this key in requests to Apigee to establish identity. Save the key.

## Use your API Key for authorization

You should now be able to access your service again. Just include the API Key in your request:

    APIKEY=yourkey
    curl -i http://$hybridHostAlias/httpbin/headers -H "x-api-key: $APIKEY"

## Next steps

That's the basics! There's a lot more you can do including:

* Hit the quota. (We set it to 5 per minute, run that curl a few more times.)
* Generate and use JWT tokens with OAuth scopes.
* Access analytics (see the `Analyze` menu in the Apigee UI).
* Use the CLI to control bindings.
* Create custom authorization rules.

But that's in another doc.

Enjoy!
