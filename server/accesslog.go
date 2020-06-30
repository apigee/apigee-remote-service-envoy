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
	"strings"

	"github.com/apigee/apigee-remote-service-golib/analytics"
	"github.com/apigee/apigee-remote-service-golib/log"
	als "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v2"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/duration"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"google.golang.org/grpc"
)

const gatewaySource = "envoy"

// AccessLogServer server
type AccessLogServer struct {
	handler *Handler
}

// Register registers
func (a *AccessLogServer) Register(s *grpc.Server, handler *Handler) {
	als.RegisterAccessLogServiceServer(s, a)
	a.handler = handler
}

// StreamAccessLogs streams
func (a *AccessLogServer) StreamAccessLogs(srv als.AccessLogService_StreamAccessLogsServer) error {
	msg, err := srv.Recv()
	if err != nil {
		return err
	}

	switch msg := msg.GetLogEntries().(type) {

	case *als.StreamAccessLogsMessage_HttpLogs:
		status := "ok"
		if err := a.handleHTTPLogs(msg); err != nil {
			status = "error"
		}
		prometheusAnalyticsRequests.WithLabelValues(a.handler.orgName, a.handler.envName, status).Inc()
		return err

	case *als.StreamAccessLogsMessage_TcpLogs:
		log.Infof("TcpLogs not supported: %#v", msg)
	}

	return nil
}

func (a *AccessLogServer) handleHTTPLogs(msg *als.StreamAccessLogsMessage_HttpLogs) error {

	for _, v := range msg.HttpLogs.LogEntry {
		req := v.Request
		api, authContext := a.handler.decodeMetadataHeaders(req.RequestHeaders)
		if api == "" {
			log.Debugf("Unknown target, skipped accesslog: %#v", v.Request)
			continue
		}

		cp := v.CommonProperties
		requestPath := strings.SplitN(req.Path, "?", 2)[0] // Apigee doesn't want query params in requestPath
		record := analytics.Record{
			ClientReceivedStartTimestamp: pbTimestampToUnix(cp.StartTime),
			ClientReceivedEndTimestamp:   pbTimestampAddDurationUnix(cp.StartTime, cp.TimeToLastRxByte),
			TargetSentStartTimestamp:     pbTimestampAddDurationUnix(cp.StartTime, cp.TimeToFirstUpstreamTxByte),
			TargetSentEndTimestamp:       pbTimestampAddDurationUnix(cp.StartTime, cp.TimeToLastUpstreamTxByte),
			TargetReceivedStartTimestamp: pbTimestampAddDurationUnix(cp.StartTime, cp.TimeToFirstUpstreamRxByte),
			TargetReceivedEndTimestamp:   pbTimestampAddDurationUnix(cp.StartTime, cp.TimeToLastUpstreamRxByte),
			ClientSentStartTimestamp:     pbTimestampAddDurationUnix(cp.StartTime, cp.TimeToFirstDownstreamTxByte),
			ClientSentEndTimestamp:       pbTimestampAddDurationUnix(cp.StartTime, cp.TimeToLastDownstreamTxByte),
			APIProxy:                     api,
			RequestURI:                   req.Path,
			RequestPath:                  requestPath,
			RequestVerb:                  req.RequestMethod.String(),
			UserAgent:                    req.UserAgent,
			ResponseStatusCode:           int(v.Response.ResponseCode.Value),
			GatewaySource:                gatewaySource,
			ClientIP:                     req.GetForwardedFor(),
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

// timeToUnix converts a time to a UNIX timestamp in milliseconds.
func pbTimestampToUnix(ts *timestamp.Timestamp) int64 {
	t, err := ptypes.Timestamp(ts)
	if err != nil {
		log.Debugf("invalid timestamp: %s", err)
		return 0
	}
	return t.UnixNano() / 1000000
}

func pbTimestampAddDurationUnix(ts *timestamp.Timestamp, d *duration.Duration) int64 {
	t, err := ptypes.Timestamp(ts)
	if err != nil {
		log.Debugf("invalid timestamp: %s", err)
		return 0
	}
	du, err := ptypes.Duration(d)
	if err != nil {
		du = 0
	}
	return t.Add(du).UnixNano() / 1000000
}

var (
	prometheusAnalyticsRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Subsystem: "analytics",
		Name:      "analytics_requests_count",
		Help:      "Total number of analytics streaming requests received",
	}, []string{"org", "env", "status"})
)
