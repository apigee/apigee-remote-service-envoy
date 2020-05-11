# Configuring Apigee for Remote Service

## How Apigee's API Products settings work

Apigee API Products are the primary control point for Apigee Remote Service.
When you create an API Product and bind it to a target, you're actually creating 
a rule set that will be applied to any requests that you configure your Envoy proxy
to intercept and send to the apigee-remote-service-envoy server.

### API Product definition

When you define an API Product in Apigee, you can set a number of parameters that
will be used to evaluate requests:

* Target
* Request path
* Quota
* OAuth scopes

#### Remote Service Targets

The API Product definition will apply to a request if the request matches both the target
binding and the request path. A list of potential targets is stored as an attribute on the 
API Product.

(By default, the Apigee Remote Service checks Envoy's special :authority (host) header against
its list of targets, however it can be configured to use other headers.)

#### API Resource Path

The entered Path matches according to the following rules:

* A single slash (/) by itself matches any path.
* is valid anywhere and matches within a segment (between slashes).
* ** is valid at the end and matches anything to the end of line.

#### Quota

Unlike within the Apigee runtime, Quotas entered in the Product definition are 
automatically enforced by the Apigee Remote Service. If the request is authorized,
the request will counted against the allowed quota.

Quotas are maintained and checked locally by the Remote Service process and asynchronously
maintained with Apigee Runtime. This means the quotas are not precised and likely to have
some overrun if you have more than one Remote Service that is maintaining the quota. If the
connection to Apigee Runtime is disrupted, the local quota will continue as a stand-alone
quota until such time as it can reconnect to the Apigee Runtime.

#### OAuth Scopes

If you're using JWT tokens, you may restrict the tokens to subsets of the allowed OAuth scopes.
The scopes assigned to your issued JWT token will be checked against the API Product's scopes.

## Apigee Apps

Once you've configured your API Products, you will create an App associated with a Developer. The app
allows a client access to the associated API Products via an API Key or JWT Token.

## Sample

Let's create an API Product to define policy for an `httpbin` target. You'll see that we actually add 
two targets: `httpbin.default.svc.cluster.local` or `httpbin.org` - so whether you're trying this with 
the Istio/Kubernetes deployment sample or accessing the httpbin.org website, it should work either way.

First, log into your Apigee UI.

Click on `API Products` then click the blue `+ API Product` button.

* In the `Product Details` section, set the name to `httpbin`.
* Select your environment(s).
* Set `Access` to `Private`.
* Set the `Quota` to `5` requests every `1` `minute`.
* Add a `Path` with the `+Custom Resource` button. Set the path to `/`.
* Create a `Custom attribute` with key: `apigee-remote-service-targets` and value: `httpbin.org,httpbin.default.svc.cluster.local`.
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
* You can use this key for authorization of your managed requests.
