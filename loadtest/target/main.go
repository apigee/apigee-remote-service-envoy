package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/apigee/apigee-remote-service-golib/util"
)

func main() {
	var addr string
	flag.StringVar(&addr, "addr", "", "address, default is random free port")
	flag.Parse()

	if addr == "" {
		p, err := util.FreePort()
		if err != nil {
			log.Fatal(err)
		}
		addr = fmt.Sprintf(":%d", p)
	}

	ts := &TestServer{}
	defer ts.Close()

	ts.srv = &http.Server{
		Addr:    addr,
		Handler: ts.Handler(),
	}

	fmt.Printf("URL: %s", ts.URL())
	_ = ts.srv.ListenAndServe()
	select {} // forever
}

type (
	TestServer struct {
		srv *http.Server
	}
)

func (ts *TestServer) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("OK"))
	})
	return m
}

func (ts *TestServer) Close() { ts.srv.Close() }

func (ts *TestServer) URL() string {
	split := strings.Split(ts.srv.Addr, ":")
	var host, port string
	port = ts.srv.Addr
	if len(split) > 1 {
		host = split[0]
		port = split[1]
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("http://%s:%s", host, port)
}
