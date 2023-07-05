module github.com/apigee/apigee-remote-service-envoy/v2

go 1.16

//replace github.com/apigee/apigee-remote-service-golib/v2 => ../apigee-remote-service-golib

require (
	github.com/apigee/apigee-remote-service-golib/v2 v2.1.1
	github.com/envoyproxy/go-control-plane v0.10.3
	github.com/gogo/googleapis v1.4.1
	github.com/golang/protobuf v1.5.2
	github.com/google/go-cmp v0.5.9
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/lestrrat-go/jwx v1.1.6
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.12.1
	github.com/spf13/cobra v1.1.3
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.16.0
	golang.org/x/oauth2 v0.4.0
	google.golang.org/genproto v0.0.0-20230110181048-76db0878b65f
	google.golang.org/grpc v1.53.0
	google.golang.org/protobuf v1.28.1
	gopkg.in/check.v1 v1.0.0-20200902074654-038fdea0a05b // indirect
	gopkg.in/yaml.v3 v3.0.1
)
