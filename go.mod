module github.com/apigee/apigee-remote-service-envoy

go 1.13

// replace github.com/apigee/apigee-remote-service-golib => ../apigee-remote-service-golib

require (
	github.com/apigee/apigee-remote-service-golib v1.0.0-beta.3.0.20200626215319-903f25c9a17d
	github.com/envoyproxy/go-control-plane v0.9.5
	github.com/gogo/googleapis v1.4.0
	github.com/golang/protobuf v1.4.2
	github.com/google/go-cmp v0.5.0
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/hashicorp/go-multierror v1.1.0
	github.com/lestrrat-go/jwx v1.0.2
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.7.1
	github.com/prometheus/common v0.10.0
	github.com/spf13/cobra v1.0.0
	go.uber.org/zap v1.15.0
	golang.org/x/net v0.0.0-20200602114024-627f9648deb9 // indirect
	google.golang.org/genproto v0.0.0-20200618031413-b414f8b61790
	google.golang.org/grpc v1.29.1
	gopkg.in/yaml.v3 v3.0.0-20200615113413-eeeca48fe776
)
