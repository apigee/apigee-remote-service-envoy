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

	"github.com/apigee/apigee-remote-service-golib/v2/analytics"
	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/product"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	v3 "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
	als "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
)

func makeExtAuthMetadata() (*structpb.Struct, error) {
	fields := map[string]interface{}{
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
	return structpb.NewStruct(fields)
}

func TestHandleHTTPAccessLogs(t *testing.T) {

	now := time.Now()
	nowUnix := now.UnixNano() / 1000000
	nowProto := timestamppb.New(now)

	dur := 7 * time.Millisecond
	thenUnix := now.Add(dur).UnixNano() / 1000000
	durProto := durationpb.New(dur)

	extAuthzMetadata, err := makeExtAuthMetadata()
	if err != nil {
		t.Fatal(err)
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
			Metadata: &core.Metadata{
				FilterMetadata: map[string]*structpb.Struct{
					extAuthzFilterNamespace: extAuthzMetadata,
					datacaptureNamespace: {
						Fields: map[string]*structpb.Value{
							"string": structpb.NewStringValue("yellow"),
							"number": structpb.NewNumberValue(3.14),
							"bool":   structpb.NewBoolValue(true),
						},
					},
				},
			},
		},
		Request: &v3.HTTPRequestProperties{
			Path:          uri,
			RequestMethod: core.RequestMethod_GET,
			UserAgent:     userAgent,
			ForwardedFor:  clientIP,
		},
		Response: &v3.HTTPResponseProperties{
			ResponseCode: &wrapperspb.UInt32Value{
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
			orgName:      extAuthzMetadata.Fields[headerOrganization].GetStringValue(),
			envName:      extAuthzMetadata.Fields[headerEnvironment].GetStringValue(),
			analyticsMan: testAnalyticsMan,
		},
		gatewaySource: managedGatewaySource,
	}
	if err := server.handleHTTPLogs(msg); err != nil {
		t.Fatal(err)
	}

	recs := testAnalyticsMan.records
	if len(recs) != len(entries) {
		t.Fatalf("got: %d, want: %d", len(recs), len(entries))
	}

	rec := recs[0]
	if rec.APIProxy != extAuthzMetadata.Fields[headerAPI].GetStringValue() {
		t.Errorf("got: %s, want: %s", rec.APIProxy, extAuthzMetadata.Fields[headerAPI].GetStringValue())
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
	if rec.GatewaySource != managedGatewaySource {
		t.Errorf("got: %s, want: %s", rec.GatewaySource, managedGatewaySource)
	}

	attrMap := make(map[string]interface{})
	for _, attr := range rec.Attributes {
		attrMap[attr.Name] = attr.Value
	}
	if attrMap["string"] != "yellow" {
		t.Errorf("got: %v, want: %v", attrMap["string"], "yellow")
	}
	if attrMap["number"] != float64(3.14) {
		t.Errorf("got: %v, want: %v", attrMap["number"], float64(3.14))
	}
	if attrMap["bool"] != true {
		t.Errorf("got: %v, want: %v", attrMap["bool"], true)
	}
	if _, ok := attrMap["struct"]; ok {
		t.Errorf("got: %v, want: nil", attrMap["struct"])
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

	nowProto := timestamppb.New(now)
	got := pbTimestampToApigee(nowProto)
	if got != want {
		t.Errorf("got: %d, want: %d", got, want)
	}

	got = pbTimestampToApigee(nil)
	if got != 0 {
		t.Errorf("got: %d, want: %d", got, 0)
	}
}

func TestAddDurationApigee(t *testing.T) {
	now := time.Now()
	duration := 6 * time.Minute
	want := now.Add(duration).UnixNano() / 1000000

	nowProto := timestamppb.New(now)
	durationProto := durationpb.New(duration)
	got := pbTimestampAddDurationApigee(nowProto, durationProto)

	if got != want {
		t.Errorf("got: %d, want: %d", got, want)
	}

	got = pbTimestampAddDurationApigee(nil, durationProto)
	if got != 0 {
		t.Errorf("got: %d, want: %d", got, 0)
	}

	got = pbTimestampAddDurationApigee(nowProto, nil)
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

	for _, rec := range records {
		rec = rec.EnsureFields(authContext)
		a.records = append(a.records, rec)
	}

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

	logMsgs := []*als.StreamAccessLogsMessage{
		makeValidHTTPLog(t),
		makeHTTPLogWithoutCommonProperties(),
		makeHTTPLogWithoutMetadata(),
		makeHTTPLogWithoutExtAuthFilterMetadata(),
		makeHTTPLogWithUnknownTarget(),
		makeTCPLog(),
		{}, // empty one,
	}

	for _, v := range logMsgs {
		if err := stream.Send(v); err != nil {
			t.Error(err)
		}
	}

	if _, err := stream.CloseAndRecv(); err != nil && err != io.EOF {
		t.Error(err)
	}

	stream, err = client.StreamAccessLogs(ctx)
	if err != nil {
		t.Fatalf("failed to open client stream: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := stream.Send(&als.StreamAccessLogsMessage{}); err != io.EOF {
		t.Error("server should have closed the stream")
	}
	if _, err := stream.CloseAndRecv(); err != nil && err == io.EOF {
		t.Error("server should have closed the stream and responded nil, but not got error marshalling it")
	}
}

func TestPrometheusProxyRecord(t *testing.T) {
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

	tests := []struct {
		desc      string
		counter   *prometheus.CounterVec
		wantCount int
		labels    []string
	}{
		{
			desc:    "proxy request count",
			counter: prometheusProxyRequestCount,
			labels:  []string{"proxy", "GET"},
		},
		{
			desc:    "proxy response count",
			counter: prometheusProxyResponseCount,
			labels:  []string{"proxy", "GET", "500", "fault-code", "fault-src"},
		},
	}

	// derive wanted counts from current ones before sending a log entry
	for i := range tests {
		tests[i].wantCount = int(testutil.ToFloat64(tests[i].counter.WithLabelValues(tests[i].labels...))) + 1
	}

	if err := stream.Send(makeValidHTTPLog(t)); err != nil {
		t.Error(err)
	}

	if _, err := stream.CloseAndRecv(); err != nil && err != io.EOF {
		t.Error(err)
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			count := int(testutil.ToFloat64(test.counter.WithLabelValues(test.labels...)))
			if count != test.wantCount {
				t.Errorf("want prometheus metric with labels %v count %d, got %d", test.labels, test.wantCount, count)
			}
		})
	}
}

type testAccessLogService struct {
	listener *bufconn.Listener
}

func (tals *testAccessLogService) startAccessLogServer(t *testing.T) *grpc.Server {
	srv := grpc.NewServer()

	testAnalyticsMan := &testAnalyticsMan{}
	h := &Handler{
		orgName:               "hi",
		envName:               "test",
		analyticsMan:          testAnalyticsMan,
		appendMetadataHeaders: true,
		operationConfigType:   product.ProxyOperationConfigType,
	}
	server := AccessLogServer{}

	server.Register(srv, h, 5*time.Millisecond, context.Background())

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

func makeValidHTTPLog(t *testing.T) *als.StreamAccessLogsMessage {
	extAuthMetadata, err := makeExtAuthMetadata()
	if err != nil {
		t.Fatal(err)
	}
	return &als.StreamAccessLogsMessage{
		LogEntries: &als.StreamAccessLogsMessage_HttpLogs{
			HttpLogs: &als.StreamAccessLogsMessage_HTTPAccessLogEntries{
				LogEntry: []*v3.HTTPAccessLogEntry{
					{
						Request: &v3.HTTPRequestProperties{
							RequestHeaders: map[string]string{
								":authority": "api",
							},
							RequestMethod: core.RequestMethod_GET,
						},
						Response: &v3.HTTPResponseProperties{
							ResponseCode: &wrapperspb.UInt32Value{
								Value: 500,
							},
							ResponseHeaders: map[string]string{
								headerProxy:       "proxy",
								headerFaultCode:   "fault-code",
								headerFaultSource: "fault-src",
							},
						},
						CommonProperties: &v3.AccessLogCommon{
							Metadata: &core.Metadata{
								FilterMetadata: map[string]*structpb.Struct{
									extAuthzFilterNamespace: extAuthMetadata,
								},
							},
							TimeToLastUpstreamTxByte: durationpb.New(time.Millisecond),
						},
					},
				},
			},
		},
	}
}

func makeHTTPLogWithUnknownTarget() *als.StreamAccessLogsMessage {
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
						CommonProperties: &v3.AccessLogCommon{
							Metadata: &core.Metadata{
								FilterMetadata: map[string]*structpb.Struct{
									extAuthzFilterNamespace: {},
								},
							},
						},
					},
				},
			},
		},
	}
}

func makeHTTPLogWithoutCommonProperties() *als.StreamAccessLogsMessage {
	return &als.StreamAccessLogsMessage{
		LogEntries: &als.StreamAccessLogsMessage_HttpLogs{
			HttpLogs: &als.StreamAccessLogsMessage_HTTPAccessLogEntries{
				LogEntry: []*v3.HTTPAccessLogEntry{
					{
						Request: &v3.HTTPRequestProperties{
							RequestHeaders: map[string]string{
								":authority": "api",
							},
						},
						Response: &v3.HTTPResponseProperties{},
					},
				},
			},
		},
	}
}

func makeHTTPLogWithoutMetadata() *als.StreamAccessLogsMessage {
	return &als.StreamAccessLogsMessage{
		LogEntries: &als.StreamAccessLogsMessage_HttpLogs{
			HttpLogs: &als.StreamAccessLogsMessage_HTTPAccessLogEntries{
				LogEntry: []*v3.HTTPAccessLogEntry{
					{
						Request: &v3.HTTPRequestProperties{
							RequestHeaders: map[string]string{
								":authority": "api",
							},
						},
						Response:         &v3.HTTPResponseProperties{},
						CommonProperties: &v3.AccessLogCommon{},
					},
				},
			},
		},
	}
}

func makeHTTPLogWithoutExtAuthFilterMetadata() *als.StreamAccessLogsMessage {
	return &als.StreamAccessLogsMessage{
		LogEntries: &als.StreamAccessLogsMessage_HttpLogs{
			HttpLogs: &als.StreamAccessLogsMessage_HTTPAccessLogEntries{
				LogEntry: []*v3.HTTPAccessLogEntry{
					{
						Request: &v3.HTTPRequestProperties{
							RequestHeaders: map[string]string{
								":authority": "api",
							},
						},
						Response: &v3.HTTPResponseProperties{},
						CommonProperties: &v3.AccessLogCommon{
							Metadata: &core.Metadata{
								FilterMetadata: map[string]*structpb.Struct{},
							},
						},
					},
				},
			},
		},
	}
}

func makeTCPLog() *als.StreamAccessLogsMessage {
	return &als.StreamAccessLogsMessage{
		LogEntries: &als.StreamAccessLogsMessage_TcpLogs{
			TcpLogs: &als.StreamAccessLogsMessage_TCPAccessLogEntries{},
		},
	}
}
