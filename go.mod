module github.com/apigee/apigee-remote-service-envoy

go 1.15

// replace github.com/apigee/apigee-remote-service-golib => ../apigee-remote-service-golib

require (
	github.com/apigee/apigee-remote-service-golib v1.3.0-rc.2
	github.com/envoyproxy/go-control-plane v0.9.7
	github.com/gogo/googleapis v1.4.0
	github.com/golang/protobuf v1.4.3
	github.com/google/go-cmp v0.5.2
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/hashicorp/go-multierror v1.1.0
	github.com/lestrrat-go/jwx v1.0.5
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.8.0
	github.com/prometheus/common v0.15.0
	github.com/spf13/cobra v1.1.1
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.16.0
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b // indirect
	golang.org/x/oauth2 v0.0.0-20201109201403-9fd604954f58
	golang.org/x/sys v0.0.0-20201109165425-215b40eba54c // indirect
	golang.org/x/text v0.3.4 // indirect
	golang.org/x/tools v0.0.0-20201110124207-079ba7bd75cd // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20201110150050-8816d57aaa9a
	google.golang.org/grpc v1.33.2
	google.golang.org/protobuf v1.25.0
	gopkg.in/yaml.v3 v3.0.0-20200615113413-eeeca48fe776
)
