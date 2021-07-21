module github.com/apigee/apigee-remote-service-envoy/loadtest/apigee

go 1.16

// Viper pulls in github.com/hashicorp/hcl which has a MPL license.
// We don't need or use this library, so replace it with a local shim.
replace github.com/hashicorp/hcl => ../../hcl_shim

require (
	github.com/apigee/apigee-remote-service-envoy/v2 v2.0.2-0.20210707154812-b7298c5084db
	github.com/apigee/apigee-remote-service-golib/v2 v2.0.2-0.20210610151449-0bc2b615ebe9
	github.com/lestrrat-go/jwx v1.2.0
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)
