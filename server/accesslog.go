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
	"google.golang.org/grpc"
)

const gatewaySource = "envoy"

// AccessLogServer server
type AccessLogServer struct {
	handler *handler
}

// Register registers
func (a *AccessLogServer) Register(s *grpc.Server, handler *handler) {
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

		// var records = make([]analytics.Record, 0, len(msg.HttpLogs.LogEntry))

		for _, v := range msg.HttpLogs.LogEntry {
			// log.Infof("HttpLogs: %#v", v)
			// log.Infof("CommonProperties: %#v", v.CommonProperties)
			// log.Infof("Request: %#v", v.Request)
			// log.Infof("Request Headers: %#v", v.Request.RequestHeaders)
			// log.Infof("Response: %#v", v.Response)
			log.Infof("DownstreamLocalAddress: %#v", v.CommonProperties.DownstreamLocalAddress)
			log.Infof("DownstreamRemoteAddress: %#v", v.CommonProperties.DownstreamRemoteAddress.GetAddress())
			log.Infof("DownstreamDirectRemoteAddress: %#v", v.CommonProperties.DownstreamDirectRemoteAddress.GetAddress())
			log.Infof("UpstreamLocalAddress: %#v", v.CommonProperties.UpstreamLocalAddress.GetAddress())
			log.Infof("UpstreamRemoteAddress: %#v", v.CommonProperties.UpstreamRemoteAddress.GetAddress())
			log.Infof("UpstreamCluster: %#v", v.CommonProperties.UpstreamCluster)

			cp := v.CommonProperties
			req := v.Request
			record := analytics.Record{
				ClientReceivedStartTimestamp: timeToUnix(cp.StartTime),
				ClientReceivedEndTimestamp:   add(cp.StartTime, cp.TimeToLastRxByte),
				ClientSentStartTimestamp:     add(cp.StartTime, cp.TimeToFirstUpstreamTxByte),
				ClientSentEndTimestamp:       add(cp.StartTime, cp.TimeToLastUpstreamTxByte),
				TargetReceivedStartTimestamp: add(cp.StartTime, cp.TimeToFirstUpstreamRxByte),
				TargetReceivedEndTimestamp:   add(cp.StartTime, cp.TimeToLastUpstreamRxByte),
				TargetSentStartTimestamp:     add(cp.StartTime, cp.TimeToFirstDownstreamTxByte),
				TargetSentEndTimestamp:       add(cp.StartTime, cp.TimeToLastDownstreamTxByte),
				APIProxy:                     cp.UpstreamCluster,
				RequestURI:                   req.Path,
				RequestVerb:                  req.RequestMethod.String(),
				UserAgent:                    req.UserAgent,
				ResponseStatusCode:           int(v.Response.ResponseCode.Value),
				GatewaySource:                gatewaySource,
				// ClientIP:                     cp.DownstreamRemoteAddress.Address, // TODO
			}

			// Apigee expects RequestURI to include query parameters. Envoy's request.path matches this.
			// However, Apigee expects RequestPath exclude query parameters. Thus, we need to drop the
			// query params from request.path for RequestPath.
			record.RequestPath = strings.SplitN(record.RequestURI, "?", 2)[0]

			if header, ok := v.Request.RequestHeaders[headerContextKey]; ok {

				// TODO: not terribly efficient, but changing requires a rewrite of underlying library
				// since it assumes the same authContext for all records and we shouldn't here
				authContext := decodeAuthContext(a.handler, header)
				records := []analytics.Record{record}
				a.handler.analyticsMan.SendRecords(authContext, records)

				// // note: the following would replace: record.EnsureFields() when we address the above
				// record.GatewayFlowID = uuid.New().String()
				// record.DeveloperEmail = authContext.DeveloperEmail
				// record.DeveloperApp = authContext.Application
				// record.AccessToken = authContext.AccessToken
				// record.ClientID = authContext.ClientID
				// record.Organization = authContext.Organization
				// record.Environment = authContext.Environment
				// if len(authContext.APIProducts) > 0 {
				// 	record.APIProduct = authContext.APIProducts[0]
				// }
			}
		}

	// TODO: support StreamAccessLogsMessage_TcpLogs?
	case *als.StreamAccessLogsMessage_TcpLogs:
		for _, v := range msg.TcpLogs.LogEntry {
			log.Infof("TcpLogs not supported: %#v", v)
		}
	}

	return nil
}

// timeToUnix converts a time to a UNIX timestamp in milliseconds.
func timeToUnix(ts *timestamp.Timestamp) int64 {
	t, err := ptypes.Timestamp(ts)
	if err != nil {
		panic(err)
	}
	return t.UnixNano() / 1000000
}

func add(ts *timestamp.Timestamp, d *duration.Duration) int64 {
	t, err := ptypes.Timestamp(ts)
	if err != nil {
		panic(err)
	}
	if d == nil {
		return t.UnixNano() / 1000000
	}
	du, err := ptypes.Duration(d)
	if err != nil {
		panic(err)
	}
	return t.Add(du).UnixNano() / 1000000
}
