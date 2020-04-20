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
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"os"

	"github.com/apigee/apigee-remote-service-envoy/server"
	"github.com/apigee/apigee-remote-service-golib/log"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
)

const (
	prometheusPath = "/metrics"
)

var (
	logLevel   string
	configFile string
)

func main() {

	rootCmd := &cobra.Command{
		Run: func(cmd *cobra.Command, args []string) {

			log.Log.SetLevel(log.ParseLevel(logLevel))

			config := server.DefaultConfig()
			if err := config.Load(configFile); err != nil {
				log.Errorf("Unable to load config: %s:\n%v", configFile, err)
				os.Exit(1)
			}

			// ManagementAPI and RemoteServiceAPI are the same for GCP Experience
			if config.Tenant.ManagementAPI == "" && config.Analytics.FluentdEndpoint != "" {
				config.Tenant.ManagementAPI = config.Tenant.RemoteServiceAPI
			}

			log.Debugf("Config: %#v", config)

			serve(config)
			select {} // infinite loop
		},
	}
	rootCmd.Flags().StringVarP(&logLevel, "log_level", "l", "info", `Logging level`)
	rootCmd.Flags().StringVarP(&configFile, "config", "c", "config.yaml", `Config file`)

	rootCmd.SetArgs(os.Args[1:])
	rootCmd.Execute()
}

func serve(config *server.Config) {

	registry := prometheus.NewRegistry()
	grpcMetrics := grpc_prometheus.NewServerMetrics()
	registry.MustRegister(grpcMetrics)

	// gRPC server
	opts := []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionAge: config.Global.KeepAliveMaxConnectionAge,
		}),
		grpc.StreamInterceptor(grpcMetrics.StreamServerInterceptor()),
		grpc.UnaryInterceptor(grpcMetrics.UnaryServerInterceptor()),
	}

	if config.Global.TLS.CertFile != "" {
		creds, err := credentials.NewServerTLSFromFile(config.Global.TLS.CertFile, config.Global.TLS.KeyFile)
		if err != nil {
			panic(err)
		}
		opts = append(opts, grpc.Creds(creds))
	}
	grpcServer := grpc.NewServer(opts...)

	// Apigee Remote Service
	rsHandler, err := server.NewHandler(config)
	if err != nil {
		log.Errorf("gRPC NewHandler: %v", err)
		panic(err)
	}
	as := &server.AuthorizationServer{}
	as.Register(grpcServer, rsHandler)
	ls := &server.AccessLogServer{}
	ls.Register(grpcServer, rsHandler)

	// health
	health := health.NewServer()
	health.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(grpcServer, health)

	// grpc listener
	grpcListener, err := net.Listen("tcp", config.Global.APIAddress)
	if err != nil {
		panic(err)
	}

	log.Infof("listening: %s\n", config.Global.APIAddress)
	go grpcServer.Serve(grpcListener)

	// prometheus listener
	metricsListener, err := net.Listen("tcp", config.Global.MetricsAddress)
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.Handle(prometheusPath, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		in := &grpc_health_v1.HealthCheckRequest{}
		response, err := health.Check(context.Background(), in)
		if err != nil {
			w.Write([]byte(err.Error()))
		} else {
			if response.Status != grpc_health_v1.HealthCheckResponse_SERVING {
				w.WriteHeader(500)
			}
			w.Write([]byte(response.Status.String()))
		}
	})

	httpServer := &http.Server{
		Addr:    config.Global.MetricsAddress,
		Handler: mux,
	}
	if config.Global.TLS.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(config.Global.TLS.CertFile, config.Global.TLS.KeyFile)
		if err != nil {
			panic(err)
		}
		httpServer.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2"},
		}
		metricsListener = tls.NewListener(metricsListener, httpServer.TLSConfig)
	}

	log.Infof("listening: %s\n", config.Global.MetricsAddress)
	go httpServer.Serve(metricsListener)
}
