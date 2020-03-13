module github.com/apigee/apigee-proxy-envoy

go 1.13

replace github.com/apigee/apigee-proxy-go => github.com/theganyo/apigee-proxy-go v0.0.0-20200310211753-749ef7c33c7c

// replace github.com/apigee/apigee-proxy-go => ../apigee-proxy-go

replace github.com/apigee/apigee-proxy-envoy => ./

require (
	github.com/apigee/apigee-proxy-go v0.0.0-00010101000000-000000000000
	github.com/envoyproxy/go-control-plane v0.9.4
	github.com/gogo/googleapis v1.3.2
	github.com/golang/protobuf v1.3.3
	github.com/google/uuid v1.1.1
	github.com/spf13/cobra v0.0.6
	golang.org/x/net v0.0.0-20200226121028-0de0cce0169b
	google.golang.org/genproto v0.0.0-20200225123651-fc8f55426688
	google.golang.org/grpc v1.27.1
	gopkg.in/yaml.v2 v2.2.7
)
