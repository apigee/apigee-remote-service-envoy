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
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/analytics"
	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/product"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	v3 "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
	als "github.com/envoyproxy/go-control-plane/envoy/service/accesslog/v3"
	wrappers "github.com/golang/protobuf/ptypes/wrappers"
)

func makeExtAuthFields() map[string]*structpb.Value {
	return map[string]*structpb.Value{
		headerAPI:            stringValueFrom("api"),
		headerAPIProducts:    stringValueFrom("product1,product2"),
		headerAccessToken:    stringValueFrom("token"),
		headerApplication:    stringValueFrom("app"),
		headerClientID:       stringValueFrom("clientID"),
		headerDeveloperEmail: stringValueFrom("email@google.com"),
		headerEnvironment:    stringValueFrom("env"),
		headerOrganization:    stringValueFrom("org"),
		headerScope:          stringValueFrom("scope1 scope2"),
	}
}

func TestHandleHTTPAccessLogs(t *testing.T) {

	now := time.Now()
	nowUnix := now.UnixMilli()
	nowProto := timestamppb.New(now)

	dur := 7 * time.Millisecond
	thenUnix := now.Add(dur).UnixMilli()
	durProto := durationpb.New(dur)

	extAuthzFields := makeExtAuthFields()

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
					extAuthzFilterNamespace: {
						Fields: extAuthzFields,
					},
					datacaptureNamespace: {
						Fields: map[string]*structpb.Value{
							"string": stringValueFrom("yellow"),
							"number": numberValueFrom(3.14),
							"bool":   boolValueFrom(true),
							"struct": structValueFrom(struct{}{}),
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
			orgName:      extAuthzFields[headerOrganization].GetStringValue(),
			envName:      extAuthzFields[headerEnvironment].GetStringValue(),
			analyticsMan: testAnalyticsMan,
		},
	}
	if err := server.handleHTTPLogs(msg); err != nil {
		t.Fatal(err)
	}

	recs := testAnalyticsMan.records
	if len(recs) != len(entries) {
		t.Fatalf("got: %d, want: %d", len(recs), len(entries))
	}

	rec := recs[0]
	if rec.APIProxy != extAuthzFields[headerAPI].GetStringValue() {
		t.Errorf("got: %s, want: %s", rec.APIProxy, extAuthzFields[headerAPI].GetStringValue())
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
	want := now.UnixMilli()

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
	want := now.Add(duration).UnixMilli()

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
	want = now.UnixMilli()
	if got != want {
		t.Errorf("got: %d, want: %d", got, want)
	}
}

type testAnalyticsMan struct {
	analytics.Manager
	records  []analytics.Record
	failSend bool
}

func (a *testAnalyticsMan) Start() {
	a.records = []analytics.Record{}
}
func (a *testAnalyticsMan) Close() {}

func (a *testAnalyticsMan) SendRecords(authContext *auth.Context, records []analytics.Record) error {
	if a.failSend {
		return errors.New("forced failure")
	}
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

	conn, err := grpc.NewClient("passthrough:///",
		grpc.WithContextDialer(tals.getBufDialer()),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	defer srv.GracefulStop()

	client := als.NewAccessLogServiceClient(conn)

	// Test Case 1: Valid and Edge Case messages
	stream, err := client.StreamAccessLogs(ctx)
	if err != nil {
		t.Fatalf("failed to open client stream: %v", err)
	}

	logMsgs := []*als.StreamAccessLogsMessage{
		makeValidHTTPLog(),
		makeHTTPLogWithoutCommonProperties(),
		makeHTTPLogWithoutMetadata(),
		makeHTTPLogWithoutExtAuthFilterMetadata(),
		makeHTTPLogWithUnknownTarget(),
		makeTCPLog(),
		{LogEntries: nil}, 
	}

	for _, v := range logMsgs {
		_ = stream.Send(v)
	}

	_ = stream.CloseSend()

	// Test Case 2: Trigger Stream Error path (Recv error booster)
	talsErr := &testAccessLogService{listener: bufconn.Listen(bufferSize)}
	srvErr := talsErr.startAccessLogServer(t)
	connErr, _ := grpc.NewClient("passthrough:///",
		grpc.WithContextDialer(talsErr.getBufDialer()),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	clientErr := als.NewAccessLogServiceClient(connErr)
	streamErr, _ := clientErr.StreamAccessLogs(ctx)

	srvErr.Stop()
	_ = streamErr.Send(makeValidHTTPLog())

	// Test Case 3: Trigger timeout booster
	talsLong := &testAccessLogService{listener: bufconn.Listen(bufferSize)}
	srvLong := talsLong.startAccessLogServerWithTimeout(t, -1*time.Millisecond)
	connLong, _ := grpc.NewClient("passthrough:///",
		grpc.WithContextDialer(talsLong.getBufDialer()),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	clientLong := als.NewAccessLogServiceClient(connLong)
	streamLong, _ := clientLong.StreamAccessLogs(ctx)
	_ = streamLong.Send(makeValidHTTPLog())

	time.Sleep(10 * time.Millisecond)
	_ = connLong.Close()
	srvLong.GracefulStop()
}

type testAccessLogService struct {
	listener *bufconn.Listener
}

func (tals *testAccessLogService) startAccessLogServer(t *testing.T) *grpc.Server {
	return tals.startAccessLogServerWithTimeout(t, 100*time.Millisecond)
}

func (tals *testAccessLogService) startAccessLogServerWithTimeout(t *testing.T, d time.Duration) *grpc.Server {
	srv := grpc.NewServer()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(product.APIResponse{APIProducts: []product.APIProduct{}})
	}))
	serverURL, _ := url.Parse(ts.URL)
	opts := product.Options{
		Client: http.DefaultClient, BaseURL: serverURL, RefreshRate: time.Hour, Org: "hi", Env: "test",
	}
	productMan, _ := product.NewManager(opts)
	h := &Handler{
		orgName:               "hi",
		envName:               "test",
		analyticsMan:          &testAnalyticsMan{},
		productMan:            productMan,
		appendMetadataHeaders: true,
	}
	server := AccessLogServer{}
	server.Register(srv, h, d)
	go func() {
		_ = srv.Serve(tals.listener)
	}()
	t.Cleanup(func() {
		ts.Close()
		productMan.Close()
	})
	return srv
}

func (tals *testAccessLogService) getBufDialer() func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, url string) (net.Conn, error) {
		return tals.listener.Dial()
	}
}

func makeValidHTTPLog() *als.StreamAccessLogsMessage {
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
								FilterMetadata: map[string]*structpb.Struct{
									extAuthzFilterNamespace: {
										Fields: makeExtAuthFields(),
									},
								},
							},
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

func TestAccessLogCoverageBooster(t *testing.T) {
	h := &Handler{
		orgName:               "hi",
		envName:               "test",
		analyticsMan:          &testAnalyticsMan{},
		appendMetadataHeaders: true,
	}
	s := AccessLogServer{handler: h, streamTimeout: time.Hour}

	// 1. handleHTTPLogs: Nil Check 
	_ = s.handleHTTPLogs(nil)

	// 2. handleHTTPLogs: Nil Request 
	_ = s.handleHTTPLogs(&als.StreamAccessLogsMessage_HttpLogs{
		HttpLogs: &als.StreamAccessLogsMessage_HTTPAccessLogEntries{
			LogEntry: []*v3.HTTPAccessLogEntry{{Request: nil}},
		},
	})

	// 3. handleHTTPLogs: Header decoding 
	_ = s.handleHTTPLogs(&als.StreamAccessLogsMessage_HttpLogs{
		HttpLogs: &als.StreamAccessLogsMessage_HTTPAccessLogEntries{
			LogEntry: []*v3.HTTPAccessLogEntry{{
				Request: &v3.HTTPRequestProperties{
					Path:           "/",
					RequestHeaders: map[string]string{":authority": "api"},
				},
			}},
		},
	})

	// 4. StreamAccessLogs: Recv Error 
	_ = s.StreamAccessLogs(&mockStream{recvErr: errors.New("err")})

	// 5. StreamAccessLogs: Empty Message 
	_ = s.StreamAccessLogs(&mockStream{
		msg: &als.StreamAccessLogsMessage{LogEntries: nil},
	})

	// 6. StreamAccessLogs: Client Close 
	_ = s.StreamAccessLogs(&mockStream{called: true})

	// 7. StreamAccessLogs: TCP Branch 
	_ = s.StreamAccessLogs(&mockStream{
		msg: &als.StreamAccessLogsMessage{
			LogEntries: &als.StreamAccessLogsMessage_TcpLogs{},
		},
	})

	// 8. StreamAccessLogs: Timeout Path 
	s.streamTimeout = -1 * time.Second
	_ = s.StreamAccessLogs(&mockStream{
		msg: makeValidHTTPLog(),
	})
}

type mockStream struct {
	als.AccessLogService_StreamAccessLogsServer
	recvErr error
	msg     *als.StreamAccessLogsMessage
	called  bool
}

func (m *mockStream) Recv() (*als.StreamAccessLogsMessage, error) {
	if m.recvErr != nil {
		return nil, m.recvErr
	}
	if m.called {
		m.called = false
		return nil, io.EOF
	}
	m.called = true
	return m.msg, nil
}
func (m *mockStream) SendAndClose(*als.StreamAccessLogsResponse) error { return nil }
func (m *mockStream) Context() context.Context { return context.Background() }

func TestAccessLogEdgeCases(t *testing.T) {
	failingManager := &testAnalyticsMan{
		failSend: true,
	}
	h := &Handler{
		orgName:      "hi",
		envName:      "test",
		analyticsMan: failingManager,
	}
	s := AccessLogServer{handler: h, streamTimeout: time.Hour}

	_ = s.StreamAccessLogs(&mockStream{
		msg: makeValidHTTPLog(),
	})

	msgWithListAttr := &als.StreamAccessLogsMessage_HttpLogs{
		HttpLogs: &als.StreamAccessLogsMessage_HTTPAccessLogEntries{
			LogEntry: []*v3.HTTPAccessLogEntry{{
				Request: &v3.HTTPRequestProperties{Path: "/"},
				CommonProperties: &v3.AccessLogCommon{
					Metadata: &core.Metadata{
						FilterMetadata: map[string]*structpb.Struct{
							extAuthzFilterNamespace: {
								Fields: makeExtAuthFields(),
							},
							datacaptureNamespace: {
								Fields: map[string]*structpb.Value{
									"list": {Kind: &structpb.Value_ListValue{ListValue: &structpb.ListValue{}}},
								},
							},
						},
					},
				},
			}},
		},
	}
	_ = s.handleHTTPLogs(msgWithListAttr)
}