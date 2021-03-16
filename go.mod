module github.com/apigee/apigee-remote-service-envoy

go 1.16

// replace github.com/apigee/apigee-remote-service-golib => ../apigee-remote-service-golib

require (
	github.com/apigee/apigee-remote-service-golib v1.4.1-0.20210316222324-5cae521e6214
	github.com/envoyproxy/go-control-plane v0.9.9-0.20201210154907-fd9021fe5dad
	github.com/gogo/googleapis v1.4.1
	github.com/golang/protobuf v1.4.3
	github.com/google/go-cmp v0.5.5
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/hashicorp/go-multierror v1.1.1
	github.com/lestrrat-go/jwx v1.1.5
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.9.0
	github.com/spf13/cobra v1.1.3
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.16.0
	golang.org/x/net v0.0.0-20210316092652-d523dce5a7f4 // indirect
	golang.org/x/oauth2 v0.0.0-20210313182246-cd4f82c27b84
	golang.org/x/text v0.3.5 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20210315173758-2651cd453018
	google.golang.org/grpc v1.36.0
	google.golang.org/protobuf v1.25.0
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)
