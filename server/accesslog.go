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

package server

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/analytics"
	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
	"github.com/apigee/apigee-remote-service-golib/v2/product"
	v3 "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
	als "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	"github.com/golang/protobuf/ptypes/duration"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	defaultGatewaySource = "envoy"
	managedGatewaySource = "configurable"
	datacaptureNamespace = "envoy.filters.http.apigee.datacapture"
)

// AccessLogServer server
type AccessLogServer struct {
	handler       *Handler
	streamTimeout time.Duration // the duration for a stream to live
	context       context.Context
	gatewaySource string
}

// Register registers
func (a *AccessLogServer) Register(s *grpc.Server, handler *Handler, d time.Duration, ctx context.Context) {
	als.RegisterAccessLogServiceServer(s, a)
	a.handler = handler
	a.streamTimeout = d
	a.context = ctx
	a.gatewaySource = defaultGatewaySource
	if a.handler.operationConfigType == product.ProxyOperationConfigType {
		a.gatewaySource = managedGatewaySource
	}
}

// StreamAccessLogs streams
func (a *AccessLogServer) StreamAccessLogs(srv als.AccessLogService_StreamAccessLogsServer) error {
	go func() {
		select {
		case <-srv.Context().Done():
		case <-a.context.Done():
			srv.SendAndClose(nil)
		case <-time.After(a.streamTimeout):
			srv.SendAndClose(nil)
		}
	}()

	for {
		msg, err := srv.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		switch msg := msg.GetLogEntries().(type) {

		case *als.StreamAccessLogsMessage_HttpLogs:
			status := "ok"
			if err := a.handleHTTPLogs(msg); err != nil {
				status = "error"
			}
			prometheusAnalyticsRequests.WithLabelValues(a.handler.orgName, status).Inc()
			if err != nil {
				return err
			}

		case *als.StreamAccessLogsMessage_TcpLogs:
			log.Infof("TcpLogs not supported: %#v", msg)
		}
	}
}

func (a *AccessLogServer) handleHTTPLogs(msg *als.StreamAccessLogsMessage_HttpLogs) error {

	for _, v := range msg.HttpLogs.GetLogEntry() {
		// record for prometheus metrics
		prometheusProxyRecord(v)

		req := v.GetRequest()

		getMetadata := func(namespace string) *structpb.Struct {
			props := v.GetCommonProperties()
			if props == nil {
				return nil
			}
			log.Debugf("props: %#v", props)

			metadata := props.GetMetadata()
			if metadata == nil {
				return nil
			}
			log.Debugf("metadata: %#v", metadata)

			return metadata.GetFilterMetadata()[namespace]
		}

		var api string
		var authContext *auth.Context

		extAuthzMetadata := getMetadata(extAuthzFilterNamespace)
		if extAuthzMetadata != nil {
			api, authContext = a.handler.decodeExtAuthzMetadata(extAuthzMetadata.GetFields())
		} else if a.handler.appendMetadataHeaders { // only check headers if knowing it may exist
			log.Debugf("No dynamic metadata for ext_authz filter, falling back to headers")
			api, authContext = a.handler.decodeMetadataHeaders(req.GetRequestHeaders())
		} else {
			log.Debugf("No dynamic metadata for ext_authz filter, skipped accesslog: %#v", req)
			continue
		}

		if api == "" {
			log.Debugf("Unknown target, skipped accesslog: %#v", v.Request)
			continue
		}

		var attributes []analytics.Attribute
		attributesMetadata := getMetadata(datacaptureNamespace)
		if len(attributesMetadata.GetFields()) > 0 {
			for k, v := range attributesMetadata.Fields {
				attr := analytics.Attribute{
					Name: k,
				}
				switch v.GetKind().(type) {
				case *structpb.Value_NumberValue:
					attr.Value = v.GetNumberValue()
				case *structpb.Value_StringValue:
					attr.Value = v.GetStringValue()
				case *structpb.Value_BoolValue:
					attr.Value = v.GetBoolValue()

				case
					*structpb.Value_StructValue,
					*structpb.Value_ListValue:
					log.Debugf("attribute %s is unsupported type: %s", k, v.GetKind())
					continue
				}
				attributes = append(attributes, attr)
			}
			log.Debugf("custom attributes: %#v", attributes)
		}

		var responseCode int
		if c := v.GetResponse().GetResponseCode(); c != nil {
			responseCode = int(c.GetValue())
		}

		cp := v.GetCommonProperties()
		requestPath := strings.SplitN(req.Path, "?", 2)[0] // Apigee doesn't want query params in requestPath
		st := cp.GetStartTime()
		record := analytics.Record{
			ClientReceivedStartTimestamp: pbTimestampToApigee(st),
			ClientReceivedEndTimestamp:   pbTimestampAddDurationApigee(st, cp.GetTimeToLastRxByte()),
			TargetSentStartTimestamp:     pbTimestampAddDurationApigee(st, cp.GetTimeToFirstUpstreamTxByte()),
			TargetSentEndTimestamp:       pbTimestampAddDurationApigee(st, cp.GetTimeToLastUpstreamTxByte()),
			TargetReceivedStartTimestamp: pbTimestampAddDurationApigee(st, cp.GetTimeToFirstUpstreamRxByte()),
			TargetReceivedEndTimestamp:   pbTimestampAddDurationApigee(st, cp.GetTimeToLastUpstreamRxByte()),
			ClientSentStartTimestamp:     pbTimestampAddDurationApigee(st, cp.GetTimeToFirstDownstreamTxByte()),
			ClientSentEndTimestamp:       pbTimestampAddDurationApigee(st, cp.GetTimeToLastDownstreamTxByte()),
			APIProxy:                     api,
			RequestURI:                   req.GetPath(),
			RequestPath:                  requestPath,
			RequestVerb:                  req.GetRequestMethod().String(),
			UserAgent:                    req.GetUserAgent(),
			ResponseStatusCode:           responseCode,
			GatewaySource:                a.gatewaySource,
			ClientIP:                     req.GetForwardedFor(),
			Attributes:                   attributes,
		}

		// this may be more efficient to batch, but changing the golib impl would require
		// a rewrite as it assumes the same authContext for all records
		records := []analytics.Record{record}
		err := a.handler.analyticsMan.SendRecords(authContext, records)
		if err != nil {
			log.Warnf("Unable to send ax: %v", err)
			return err
		}
	}

	return nil
}

// returns ms since epoch
func pbTimestampToApigee(ts *timestamp.Timestamp) int64 {
	if err := ts.CheckValid(); err != nil {
		log.Debugf("invalid timestamp: %s", err)
		return 0
	}
	return timeToApigeeInt(ts.AsTime())
}

// returns ms since epoch
func pbTimestampAddDurationApigee(ts *timestamp.Timestamp, d *duration.Duration) int64 {
	if err := ts.CheckValid(); err != nil {
		log.Debugf("invalid timestamp: %s", err)
		return 0
	}
	du := d.AsDuration()
	if err := d.CheckValid(); err != nil {
		du = 0
	}
	return timeToApigeeInt(ts.AsTime().Add(du))
}

var (
	prometheusAnalyticsRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Subsystem: "analytics",
		Name:      "analytics_requests_count",
		Help:      "Total number of analytics streaming requests received",
	}, []string{"org", "status"})
)

// format time as ms since epoch
func timeToApigeeInt(t time.Time) int64 {
	return t.UnixNano() / (int64(time.Millisecond) / int64(time.Nanosecond))
}

func prometheusProxyRecord(logEntry *v3.HTTPAccessLogEntry) {
	if logEntry == nil {
		return
	}
	req := logEntry.GetRequest()
	resp := logEntry.GetResponse()
	method := req.GetRequestMethod().String()
	var proxyName string
	if headers := resp.GetResponseHeaders(); headers != nil {
		proxyName = headers[headerProxy]
	}

	// increment request counter
	prometheusProxyRequestCount.WithLabelValues(proxyName, method).Inc()

	// record latency
	cp := logEntry.GetCommonProperties()
	if cp != nil && cp.TimeToLastUpstreamTxByte != nil {
		responseTime := float64(cp.TimeToLastUpstreamTxByte.AsDuration().Milliseconds())
		prometheusProxyLatencies.WithLabelValues(proxyName, method).Observe(responseTime)
	}

	// increment response counter
	if resp == nil {
		return
	}
	responseCode := fmt.Sprintf("%d", resp.GetResponseCode().GetValue())
	faultCode := resp.ResponseHeaders[headerFaultCode]
	faultSource := resp.ResponseHeaders[headerFaultSource]
	prometheusProxyResponseCount.WithLabelValues(proxyName, method, responseCode, faultCode, faultSource).Inc()
}

// prometheus metrics for proxies and targets
var (
	prometheusProxyRequestCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Subsystem: "proxy",
		Name:      "request_count",
		Help:      "Total number of requests received",
	}, []string{"proxy_name", "method"})
	prometheusProxyResponseCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Subsystem: "proxy",
		Name:      "response_count",
		Help:      "Total number of responses sent",
	}, []string{"proxy_name", "method", "response_code", "fault_code", "fault_source"})
	prometheusProxyLatencies = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Subsystem: "proxy",
		Name:      "latencies",
		Help:      "Request and response latencies in milliseconds, including proxy overhead and target service time",
		// follows Apigee's convention of buckets for latencies
		Buckets: []float64{1, 2, 5, 10, 25, 50, 75, 100, 250, 500, 750, 1000, 2500, 5000, 7500, 10000},
	}, []string{"proxy_name", "method"})
)
