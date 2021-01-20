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

// Package protostruct supports operations on the protocol buffer Struct message.
package server

import (
	"context"
	"io"
	"log"
	"net"
	"testing"
	"time"

	// "github.com/gogo/status"
	"github.com/apigee/apigee-remote-service-golib/analytics"
	"github.com/apigee/apigee-remote-service-golib/auth"
	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	v3 "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
	als "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	wrappers "github.com/golang/protobuf/ptypes/wrappers"
)

func TestHandleHTTPAccessLogs(t *testing.T) {

	now := time.Now()
	nowUnix := now.UnixNano() / 1000000
	nowProto, err := ptypes.TimestampProto(now)
	if err != nil {
		t.Fatal(err)
	}

	dur := 7 * time.Millisecond
	thenUnix := now.Add(dur).UnixNano() / 1000000
	durProto := ptypes.DurationProto(dur)

	headers := map[string]string{
		headerAPI:            "api",
		headerAPIProducts:    "product1,product2",
		headerAccessToken:    "token",
		headerApplication:    "app",
		headerClientID:       "clientID",
		headerDeveloperEmail: "email@google.com",
		headerEnvironment:    "env",
		headerOrganization:   "org",
		headerScope:          "scope1 scope2",
	}

	path := "path"
	uri := "path?x=foo"
	userAgent := "some agent"
	clientIP := "client ip"
	var entries []*v3.HTTPAccessLogEntry
	entries = append(entries, &v3.HTTPAccessLogEntry{
		CommonProperties: &v3.AccessLogCommon{
			StartTime:                   nowProto,
			TimeToLastRxByte:            durProto,
			TimeToFirstUpstreamTxByte:   durProto,
			TimeToLastUpstreamTxByte:    durProto,
			TimeToFirstUpstreamRxByte:   durProto,
			TimeToLastUpstreamRxByte:    durProto,
			TimeToFirstDownstreamTxByte: durProto,
			TimeToLastDownstreamTxByte:  durProto,
		},
		Request: &v3.HTTPRequestProperties{
			Path:           uri,
			RequestMethod:  core.RequestMethod_GET,
			UserAgent:      userAgent,
			ForwardedFor:   clientIP,
			RequestHeaders: headers,
		},
		Response: &v3.HTTPResponseProperties{
			ResponseCode: &wrappers.UInt32Value{
				Value: 200,
			},
		},
	})

	msg := &als.StreamAccessLogsMessage_HttpLogs{
		HttpLogs: &als.StreamAccessLogsMessage_HTTPAccessLogEntries{
			LogEntry: entries,
		},
	}

	testAnalyticsMan := &testAnalyticsMan{}
	server := AccessLogServer{
		handler: &Handler{
			orgName:      headers[headerOrganization],
			envName:      headers[headerEnvironment],
			analyticsMan: testAnalyticsMan,
		},
	}
	if err := server.handleHTTPLogs(msg); err != nil {
		t.Fatal(err)
	}

	recs := testAnalyticsMan.records
	if len(recs) != len(entries) {
		t.Errorf("got: %d, want: %d", len(recs), len(entries))
	}

	rec := recs[0]
	if rec.APIProxy != headers[headerAPI] {
		t.Errorf("got: %s, want: %s", rec.APIProxy, headers[headerAPI])
	}
	if rec.ClientIP != clientIP {
		t.Errorf("got: %s, want: %s", rec.ClientIP, clientIP)
	}
	if rec.ClientReceivedEndTimestamp != thenUnix {
		t.Errorf("got: %d, want: %d", rec.ClientReceivedEndTimestamp, thenUnix)
	}
	if rec.ClientReceivedStartTimestamp != nowUnix {
		t.Errorf("got: %d, want: %d", rec.ClientReceivedStartTimestamp, nowUnix)
	}
	if rec.ClientSentEndTimestamp != thenUnix {
		t.Errorf("got: %d, want: %d", rec.ClientSentEndTimestamp, thenUnix)
	}
	if rec.ClientSentStartTimestamp != thenUnix {
		t.Errorf("got: %d, want: %d", rec.ClientSentStartTimestamp, thenUnix)
	}

	// the following are handled in golib by record.ensureFields()
	// so we're skipping validation of them...

	// rec.RecordType skipped
	// product := strings.Split(headers[headerAPIProducts], ",")[0]
	// if rec.APIProduct != product {
	// 	t.Errorf("got: %s, want: %s", rec.APIProduct, product)
	// }
	// rec.APIProxyRevision skipped
	// if rec.AccessToken != headers[headerAccessToken] {
	// 	t.Errorf("got: %s, want: %s", rec.AccessToken, headers[headerAccessToken])
	// }
	// if rec.ClientID != headers[headerClientID] {
	// 	t.Errorf("got: %s, want: %s", rec.ClientID, headers[headerClientID])
	// }
	// if rec.DeveloperApp != headers[headerApplication] {
	// 	t.Errorf("got: %s, want: %s", rec.DeveloperApp, headers[headerApplication])
	// }
	// if rec.DeveloperEmail != headers[headerDeveloperEmail] {
	// 	t.Errorf("got: %s, want: %s", rec.DeveloperEmail, headers[headerDeveloperEmail])
	// }
	// if rec.Environment != headers[headerEnvironment] {
	// 	t.Errorf("got: %s, want: %s", rec.Environment, headers[headerEnvironment])
	// }
	// if rec.GatewayFlowID != flowID {
	// 	t.Errorf("got: %s, want: %s", rec.GatewayFlowID, flowID)
	// }
	// rec.GatewaySource skipped
	// if rec.Organization != headers[headerOrganization] {
	// 	t.Errorf("got: %s, want: %s", rec.Organization, headers[headerOrganization])
	// }

	if rec.RequestPath != path {
		t.Errorf("got: %s, want: %s", rec.RequestPath, path)
	}
	if rec.RequestURI != uri {
		t.Errorf("got: %s, want: %s", rec.RequestURI, uri)
	}
	if rec.RequestVerb != core.RequestMethod_GET.String() {
		t.Errorf("got: %s, want: %s", core.RequestMethod_GET.String(), uri)
	}
	if rec.ResponseStatusCode != 200 {
		t.Errorf("got: %d, want: %d", rec.ResponseStatusCode, 200)
	}

	if rec.TargetReceivedEndTimestamp != thenUnix {
		t.Errorf("got: %d, want: %d", rec.TargetReceivedEndTimestamp, thenUnix)
	}
	if rec.TargetReceivedStartTimestamp != thenUnix {
		t.Errorf("got: %d, want: %d", rec.TargetReceivedStartTimestamp, thenUnix)
	}
	if rec.TargetSentEndTimestamp != thenUnix {
		t.Errorf("got: %d, want: %d", rec.TargetSentEndTimestamp, thenUnix)
	}
	if rec.TargetSentStartTimestamp != thenUnix {
		t.Errorf("got: %d, want: %d", rec.TargetSentStartTimestamp, thenUnix)
	}
	if rec.UserAgent != userAgent {
		t.Errorf("got: %s, want: %s", rec.UserAgent, userAgent)
	}

	// missing response code can happen when client kills request
	msg.HttpLogs.LogEntry[0].Response.ResponseCode = nil
	if err := server.handleHTTPLogs(msg); err != nil {
		t.Fatal(err)
	}

	rec = testAnalyticsMan.records[len(testAnalyticsMan.records)-1]
	if rec.ResponseStatusCode != 0 {
		t.Errorf("got: %d, want: %d", rec.ResponseStatusCode, 0)
	}
}

func TestTimeToUnix(t *testing.T) {
	now := time.Now()
	want := now.UnixNano() / 1000000

	nowProto, err := ptypes.TimestampProto(now)
	if err != nil {
		t.Fatal(err)
	}
	got := pbTimestampToUnix(nowProto)
	if got != want {
		t.Errorf("got: %d, want: %d", got, want)
	}

	got = pbTimestampToUnix(nil)
	if got != 0 {
		t.Errorf("got: %d, want: %d", got, 0)
	}
}

func TestAddDurationUnix(t *testing.T) {
	now := time.Now()
	duration := 6 * time.Minute
	want := now.Add(duration).UnixNano() / 1000000

	nowProto, err := ptypes.TimestampProto(now)
	if err != nil {
		t.Fatal(err)
	}
	durationProto := ptypes.DurationProto(duration)
	got := pbTimestampAddDurationUnix(nowProto, durationProto)

	if got != want {
		t.Errorf("got: %d, want: %d", got, want)
	}

	got = pbTimestampAddDurationUnix(nil, durationProto)
	if got != 0 {
		t.Errorf("got: %d, want: %d", got, 0)
	}

	got = pbTimestampAddDurationUnix(nowProto, nil)
	want = now.UnixNano() / 1000000
	if got != want {
		t.Errorf("got: %d, want: %d", got, want)
	}
}

type testAnalyticsMan struct {
	analytics.Manager
	records []analytics.Record
}

func (a *testAnalyticsMan) Start() {
	a.records = []analytics.Record{}
}
func (a *testAnalyticsMan) Close() {}
func (a *testAnalyticsMan) SendRecords(authContext *auth.Context, records []analytics.Record) error {

	a.records = append(a.records, records...)
	return nil
}

func TestStreamAccessLogs(t *testing.T) {
	const bufferSize = 1024 * 1024

	tals := &testAccessLogService{
		listener: bufconn.Listen(bufferSize),
	}
	srv := tals.startAccessLogServer(t)
	ctx := context.Background()

	defer time.Sleep(5 * time.Millisecond)
	defer srv.GracefulStop()
	conn, err := grpc.DialContext(ctx, "", grpc.WithContextDialer(tals.getBufDialer()), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	client := als.NewAccessLogServiceClient(conn)
	stream, err := client.StreamAccessLogs(ctx)
	if err != nil {
		t.Fatalf("failed to open client stream: %v", err)
	}

	httpLog := getHTTPLog()

	if err := stream.Send(httpLog); err != nil {
		t.Error(err)
	}

	tcpLog := getTCPLog()

	if err := stream.Send(tcpLog); err != nil {
		t.Error(err)
	}

	if err := stream.Send(&als.StreamAccessLogsMessage{}); err != nil {
		t.Error(err)
	}

	if _, err := stream.CloseAndRecv(); err != nil && err != io.EOF {
		t.Error(err)
	}

	stream, err = client.StreamAccessLogs(ctx)
	if err != nil {
		t.Fatalf("failed to open client stream: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := stream.Send(&als.StreamAccessLogsMessage{}); err != nil {
		t.Error(err)
	}
	if _, err := stream.CloseAndRecv(); err == nil || err == io.EOF {
		t.Error("server should have closed the stream and responded nil, but not got error marshalling it")
	}
}

type testAccessLogService struct {
	listener *bufconn.Listener
}

func (tals *testAccessLogService) startAccessLogServer(t *testing.T) *grpc.Server {
	srv := grpc.NewServer()

	testAnalyticsMan := &testAnalyticsMan{}
	h := &Handler{
		orgName:      "hi",
		envName:      "test",
		analyticsMan: testAnalyticsMan,
	}
	server := AccessLogServer{}

	server.Register(srv, h, 5*time.Millisecond)

	go func() {
		if err := srv.Serve(tals.listener); err != nil {
			log.Fatalf("failed to start grpc server: %v", err)
		}
	}()

	return srv
}

func (tals *testAccessLogService) getBufDialer() func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, url string) (net.Conn, error) {
		return tals.listener.Dial()
	}
}

func getHTTPLog() *als.StreamAccessLogsMessage {
	return &als.StreamAccessLogsMessage{
		LogEntries: &als.StreamAccessLogsMessage_HttpLogs{
			HttpLogs: &als.StreamAccessLogsMessage_HTTPAccessLogEntries{
				LogEntry: []*v3.HTTPAccessLogEntry{
					{
						Request: &v3.HTTPRequestProperties{
							RequestHeaders: map[string]string{
								":authority": "",
							},
						},
						Response: &v3.HTTPResponseProperties{},
					},
				},
			},
		},
	}
}

func getTCPLog() *als.StreamAccessLogsMessage {
	return &als.StreamAccessLogsMessage{
		LogEntries: &als.StreamAccessLogsMessage_TcpLogs{
			TcpLogs: &als.StreamAccessLogsMessage_TCPAccessLogEntries{},
		},
	}
}
