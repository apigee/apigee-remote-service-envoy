// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"net"
	"os"

	"github.com/apigee/apigee-proxy-envoy/server"
	"github.com/apigee/apigee-proxy-go/log"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	hproto "google.golang.org/grpc/health/grpc_health_v1"
)

var address string
var logLevel string
var configFile string

func main() {

	rootCmd := &cobra.Command{
		Run: func(cmd *cobra.Command, args []string) {

			log.Log.SetLevel(log.ParseLevel(logLevel))

			lis, err := net.Listen("tcp", address)
			if err != nil {
				log.Errorf("failed to listen: %v", err)
				panic(err)
			}

			s := grpc.NewServer()

			config := server.DefaultConfig()
			if err = config.Load(configFile); err != nil {
				log.Errorf("Load config: %v", err)
				panic(err)
			}

			log.Debugf("Config: %#v", config)

			handler, err := server.NewHandler(config)
			if err != nil {
				log.Errorf("NewHandler: %v", err)
				panic(err)
			}

			as := &server.AuthorizationServer{}
			as.Register(s, handler)

			ls := &server.AccessLogServer{}
			ls.Register(s, handler)

			health := health.NewServer()
			health.SetServingStatus("", hproto.HealthCheckResponse_SERVING)
			hproto.RegisterHealthServer(s, health)

			fmt.Printf("listening on :%v\n", lis.Addr())
			s.Serve(lis)
		},
	}
	rootCmd.Flags().StringVarP(&address, "address", "a", ":5000", `Address to use for Adapter's gRPC API`)
	rootCmd.Flags().StringVarP(&logLevel, "log_level", "l", "info", `Logging level`)
	rootCmd.Flags().StringVarP(&configFile, "config", "c", "config.yaml", `Config file`)

	rootCmd.SetArgs(os.Args[1:])
	rootCmd.Execute()
}
