module github.com/apigee/apigee-remote-service-envoy/v2

go 1.16

// replace github.com/apigee/apigee-remote-service-golib/v2 => ../apigee-remote-service-golib

// Viper pulls in github.com/hashicorp/hcl which has a MPL license.
// We don't need or use this library, so replace it with a local shim.
replace github.com/hashicorp/hcl => ./hcl_shim

require (
	github.com/alecthomas/participle/v2 v2.0.0-alpha5
	github.com/apigee/apigee-remote-service-golib/v2 v2.0.2-0.20210721130449-a650cbdc1398
	github.com/envoyproxy/go-control-plane v0.9.9-0.20210217033140-668b12f5399d
	github.com/gogo/googleapis v1.4.1
	github.com/golang/protobuf v1.5.2
	github.com/google/go-cmp v0.5.5
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/lestrrat-go/jwx v1.2.0
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.10.0
	github.com/spf13/cobra v1.2.0
	github.com/spf13/viper v1.8.1
	go.uber.org/zap v1.17.0
	golang.org/x/oauth2 v0.0.0-20210402161424-2e8d93401602
	google.golang.org/genproto v0.0.0-20210602131652-f16073e35f0c
	google.golang.org/grpc v1.38.0
	google.golang.org/protobuf v1.26.0
	gopkg.in/check.v1 v1.0.0-20200902074654-038fdea0a05b // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)
