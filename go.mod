module github.com/apigee/apigee-remote-service-envoy/v2

go 1.16

// replace github.com/apigee/apigee-remote-service-golib/v2 => ../apigee-remote-service-golib

require (
	github.com/apigee/apigee-remote-service-golib/v2 v2.0.2-0.20210507235313-551e9af389a8
	github.com/envoyproxy/go-control-plane v0.9.9-0.20201210154907-fd9021fe5dad
	github.com/gogo/googleapis v1.4.1
	github.com/golang/protobuf v1.5.1
	github.com/google/go-cmp v0.5.5
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/lestrrat-go/jwx v1.1.6
	github.com/niemeyer/pretty v0.0.0-20200227124842-a10e7caefd8e // indirect
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.9.0
	github.com/spf13/cobra v1.1.3
	github.com/spf13/viper v1.7.0
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.16.0
	golang.org/x/net v0.0.0-20210316092652-d523dce5a7f4 // indirect
	golang.org/x/oauth2 v0.0.0-20210313182246-cd4f82c27b84
	golang.org/x/text v0.3.5 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20210315173758-2651cd453018
	google.golang.org/grpc v1.36.0
	google.golang.org/protobuf v1.26.0
	gopkg.in/check.v1 v1.0.0-20200902074654-038fdea0a05b // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)
