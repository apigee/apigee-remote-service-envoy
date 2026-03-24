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
	"io"
	"strings"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/analytics"
	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
	als "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	gatewaySource        = "envoy"
	datacaptureNamespace = "envoy.filters.http.apigee.datacapture"
)

// AccessLogServer server
type AccessLogServer struct {
	handler       *Handler
	streamTimeout time.Duration
}

// Register registers
func (a *AccessLogServer) Register(s *grpc.Server, handler *Handler, d time.Duration) {
	als.RegisterAccessLogServiceServer(s, a)
	a.handler = handler
	a.streamTimeout = d
}

// StreamAccessLogs streams
func (a *AccessLogServer) StreamAccessLogs(stream als.AccessLogService_StreamAccessLogsServer) error {
	endTime := time.Now().Add(a.streamTimeout)
	log.Debugf("started stream")
	defer log.Debugf("closed stream")

	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			log.Debugf("client closed stream")
			_ = stream.SendAndClose(&als.StreamAccessLogsResponse{})
			return nil
		}
		if err != nil { return err }

		// This explicit check handles the "Missing" error return line
		if msg == nil || msg.GetLogEntries() == nil {
			log.Errorf("received empty StreamAccessLogsMessage")
			return status.Errorf(codes.InvalidArgument, "received empty StreamAccessLogsMessage")
		}

		switch logs := msg.GetLogEntries().(type) {
		case *als.StreamAccessLogsMessage_HttpLogs:
			statusStr := "ok"
			if err := a.handleHTTPLogs(logs); err != nil {
				statusStr = "error"
				log.Errorf("handleHTTPLogs: %v", err)
			}
			prometheusAnalyticsRequests.WithLabelValues(a.handler.orgName, statusStr).Inc()

		case *als.StreamAccessLogsMessage_TcpLogs:
			log.Infof("TcpLogs not supported: %#v", logs)
		}

		if endTime.Before(time.Now()) {
			log.Debugf("stream timeout reached")
			_ = stream.SendAndClose(&als.StreamAccessLogsResponse{})
			return nil
		}
	}
}

func (a *AccessLogServer) handleHTTPLogs(msg *als.StreamAccessLogsMessage_HttpLogs) error {
	if msg == nil || msg.HttpLogs == nil || len(msg.HttpLogs.LogEntry) == 0 { return nil }

	for _, v := range msg.HttpLogs.LogEntry {
		req := v.Request
		if req == nil { continue } 

		getMetadata := func(namespace string) *structpb.Struct {
			props := v.GetCommonProperties()
			if props == nil || props.GetMetadata() == nil { return nil }
			return props.GetMetadata().GetFilterMetadata()[namespace]
		}

		var api string
		var authContext *auth.Context

		extAuthzMetadata := getMetadata(extAuthzFilterNamespace)
		if extAuthzMetadata != nil {
			api, authContext = a.handler.decodeExtAuthzMetadata(extAuthzMetadata.GetFields())
		} else if a.handler.appendMetadataHeaders {
			api, authContext = a.handler.decodeMetadataHeaders(req.GetRequestHeaders())
		} else {
			continue
		}

		if api == "" { continue } 

		var attributes []analytics.Attribute
		attributesMetadata := getMetadata(datacaptureNamespace)
		if attributesMetadata != nil && len(attributesMetadata.Fields) > 0 {
			for k, val := range attributesMetadata.Fields {
				attr := analytics.Attribute{Name: k}
				switch val.GetKind().(type) {
				case *structpb.Value_NumberValue: attr.Value = val.GetNumberValue()
				case *structpb.Value_StringValue: attr.Value = val.GetStringValue()
				case *structpb.Value_BoolValue:   attr.Value = val.GetBoolValue()
				default: continue
				}
				attributes = append(attributes, attr)
			}
		}

		var responseCode int
		if v.Response != nil && v.Response.ResponseCode != nil {
			responseCode = int(v.Response.ResponseCode.Value)
		}

		cp := v.CommonProperties
		requestPath := strings.SplitN(req.Path, "?", 2)[0]
		record := analytics.Record{
			ClientReceivedStartTimestamp: pbTimestampToApigee(cp.GetStartTime()),
			ClientReceivedEndTimestamp:   pbTimestampAddDurationApigee(cp.GetStartTime(), cp.GetTimeToLastRxByte()),
			TargetSentStartTimestamp:     pbTimestampAddDurationApigee(cp.GetStartTime(), cp.GetTimeToFirstUpstreamTxByte()),
			TargetSentEndTimestamp:       pbTimestampAddDurationApigee(cp.GetStartTime(), cp.GetTimeToLastUpstreamTxByte()),
			TargetReceivedStartTimestamp: pbTimestampAddDurationApigee(cp.GetStartTime(), cp.GetTimeToFirstUpstreamRxByte()),
			TargetReceivedEndTimestamp:   pbTimestampAddDurationApigee(cp.GetStartTime(), cp.GetTimeToLastUpstreamRxByte()),
			ClientSentStartTimestamp:     pbTimestampAddDurationApigee(cp.GetStartTime(), cp.GetTimeToFirstDownstreamTxByte()),
			ClientSentEndTimestamp:       pbTimestampAddDurationApigee(cp.GetStartTime(), cp.GetTimeToLastDownstreamTxByte()),
			APIProxy:                     api,
			RequestURI:                   req.Path,
			RequestPath:                  requestPath,
			RequestVerb:                  req.RequestMethod.String(),
			UserAgent:                    req.UserAgent,
			ResponseStatusCode:           responseCode,
			GatewaySource:                gatewaySource,
			ClientIP:                     req.GetForwardedFor(),
			Attributes:                   attributes,
		}

		if err := a.handler.analyticsMan.SendRecords(authContext, []analytics.Record{record}); err != nil {
			log.Warnf("Unable to send ax: %v", err)
			return err 
		}
	}
	return nil
}

// returns ms since epoch
func pbTimestampToApigee(ts *timestamppb.Timestamp) int64 {
	if ts == nil || ts.CheckValid() != nil { return 0 }
	return timeToApigeeInt(ts.AsTime())
}

// returns ms since epoch
func pbTimestampAddDurationApigee(ts *timestamppb.Timestamp, d *durationpb.Duration) int64 {
	if ts == nil || ts.CheckValid() != nil { return 0 }
	targetTime := ts.AsTime()
	if d != nil && d.CheckValid() == nil { targetTime = targetTime.Add(d.AsDuration()) }
	return timeToApigeeInt(targetTime)
}

// format time as ms since epoch
func timeToApigeeInt(t time.Time) int64 {
	return t.UnixMilli()
}

var (
	prometheusAnalyticsRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Subsystem: "analytics",
		Name:      "analytics_requests_count",
		Help:      "Total number of analytics streaming requests received",
	}, []string{"org", "status"})
)