package main

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/zalando/skipper/filters"
	"github.com/zalando/skipper/net"
)

const (
	webhookSpanName            = "webhook"
	tokenInfoSpanName          = "tokeninfo"
	tokenIntrospectionSpanName = "tokenintrospection"
)

const (
	defaultMaxIdleConns = 64
)

type authClient struct {
	url *url.URL
	cli *net.Client
}

func newAuthClient(baseURL, spanName string, timeout time.Duration, maxIdleConns int, tracer opentracing.Tracer) (*authClient, error) {
	if tracer == nil {
		tracer = opentracing.NoopTracer{}
	}
	if maxIdleConns <= 0 {
		maxIdleConns = defaultMaxIdleConns
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	cli := net.NewClient(net.Options{
		ResponseHeaderTimeout:   timeout,
		TLSHandshakeTimeout:     timeout,
		MaxIdleConnsPerHost:     maxIdleConns,
		Tracer:                  tracer,
		OpentracingComponentTag: "skipper",
		OpentracingSpanName:     spanName,
	})

	return &authClient{url: u, cli: cli}, nil
}

func (ac *authClient) Close() {
	ac.cli.Close()
}

func bindContext(ctx filters.FilterContext, req *http.Request) *http.Request {
	return req.WithContext(ctx.Request().Context())
}

func (ac *authClient) getTokeninfo(token string, ctx filters.FilterContext) (map[string]interface{}, error) {
	var doc map[string]interface{}

	req, err := http.NewRequest("GET", ac.url.String(), nil)
	if err != nil {
		return doc, err
	}

	req = bindContext(ctx, req)

	if token != "" {
		req.Header.Set(authHeaderName, authHeaderPrefix+token)
	}

	rsp, err := ac.cli.Do(req)
	if err != nil {
		return doc, err
	}
	defer rsp.Body.Close()

	if rsp.StatusCode != 200 {
		io.Copy(ioutil.Discard, rsp.Body)
		return doc, errInvalidToken
	}

	d := json.NewDecoder(rsp.Body)
	err = d.Decode(&doc)
	return doc, err
}
