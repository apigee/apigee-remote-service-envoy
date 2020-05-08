module github.com/apigee/apigee-remote-service-envoy

go 1.13

replace github.com/apigee/apigee-remote-service-golib => github.com/theganyo/apigee-remote-service-golib v0.0.4-dev.0.20200508224846-ca63c647648e

// replace github.com/apigee/apigee-remote-service-golib => ../apigee-remote-service-golib

replace github.com/apigee/apigee-remote-service-envoy => ./

require (
	github.com/apigee/apigee-remote-service-golib v0.0.0-00010101000000-000000000000
	github.com/envoyproxy/go-control-plane v0.9.5
	github.com/gogo/googleapis v1.3.2
	github.com/golang/protobuf v1.4.0
	github.com/google/go-cmp v0.4.0
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/hashicorp/go-multierror v1.1.0
	github.com/prometheus/client_golang v1.5.1
	github.com/spf13/cobra v1.0.0
	golang.org/x/net v0.0.0-20200324143707-d3edc9973b7e // indirect
	google.golang.org/genproto v0.0.0-20200417142217-fb6d0575620b
	google.golang.org/grpc v1.28.1
	gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c
)
