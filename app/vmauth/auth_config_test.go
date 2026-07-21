package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/VictoriaMetrics/VictoriaMetrics/lib/logger"
	"github.com/VictoriaMetrics/VictoriaMetrics/lib/netutil"
)

func TestParseAuthConfigFailure(t *testing.T) {
	f := func(s string) {
		t.Helper()
		ac, err := parseAuthConfig([]byte(s))
		if err != nil {
			return
		}
		users, err := parseAuthConfigUsers(ac)
		if err == nil {
			t.Fatalf("expecting non-nil error; got %v", users)
		}
	}

	// Invalid entry
	f(`foobar`)
	f(`foobar: baz`)

	// Missing url_prefix
	f(`
users:
- username: foo
`)

	// Invalid url_prefix
	f(`
users:
- username: foo
  url_prefix: bar
`)
	f(`
users:
- username: foo
  url_prefix: ftp://bar
`)
	f(`
users:
- username: foo
  url_prefix: //bar
`)
	f(`
users:
- username: foo
  url_prefix: http:///bar
`)
	f(`
users:
- username: foo
  url_prefix:
    bar: baz
`)
	f(`
users:
- username: foo
  url_prefix:
  - [foo]
`)

	// Invalid headers
	f(`
users:
- username: foo
  url_prefix: http://foo.bar
  headers: foobar
`)

	// Invalid keep_original_host value
	f(`
users:
- username: foo
  url_prefix: http://foo.bar
  keep_original_host: foobar
`)

	// empty url_prefix
	f(`
users:
- username: foo
  url_prefix: []
`)

	// auth_token and username in a single config
	f(`
users:
- auth_token: foo
  username: bbb
  url_prefix: http://foo.bar
`)

	// auth_token and bearer_token in a single config
	f(`
users:
- auth_token: foo
  bearer_token: bbb
  url_prefix: http://foo.bar
`)

	// Username and bearer_token in a single config
	f(`
users:
- username: foo
  bearer_token: bbb
  url_prefix: http://foo.bar
`)

	// Bearer_token and password in a single config
	f(`
users:
- password: foo
  bearer_token: bbb
  url_prefix: http://foo.bar
`)

	// Duplicate users
	f(`
users:
- username: foo
  url_prefix: http://foo.bar
- username: bar
  url_prefix: http://xxx.yyy
- username: foo
  url_prefix: https://sss.sss
`)
	// Duplicate users
	f(`
users:
- username: foo
  password: bar
  url_prefix: http://foo.bar
- username: bar
  url_prefix: http://xxx.yyy
- username: foo
  password: bar
  url_prefix: https://sss.sss
`)

	// Duplicate bearer_tokens
	f(`
users:
- bearer_token: foo
  url_prefix: http://foo.bar
- username: bar
  url_prefix: http://xxx.yyy
- bearer_token: foo
  url_prefix: https://sss.sss
`)

	// Missing url_prefix in url_map
	f(`
users:
- username: a
  url_map:
  - src_paths: ["/foo/bar"]
`)
	f(`
users:
- username: a
  url_map:
  - src_hosts: ["foobar"]
`)

	// Invalid url_prefix in url_map
	f(`
users:
- username: a
  url_map:
  - src_paths: ["/foo/bar"]
    url_prefix: foo.bar
`)
	f(`
users:
- username: a
  url_map:
  - src_hosts: ["foobar"]
    url_prefix: foo.bar
`)

	// empty url_prefix in url_map
	f(`
users:
- username: a
  url_map:
  - src_paths: ['/foo/bar']
    url_prefix: []
`)
	f(`
users:
- username: a
  url_map:
  - src_phosts: ['foobar']
    url_prefix: []
`)

	// Missing src_paths and src_hosts in url_map
	f(`
users:
- username: a
  url_map:
  - url_prefix: http://foobar
`)

	// Invalid regexp in src_paths
	f(`
users:
- username: a
  url_map:
  - src_paths: ['fo[obar']
    url_prefix: http://foobar
`)

	// Invalid regexp in src_hosts
	f(`
users:
- username: a
  url_map:
  - src_hosts: ['fo[obar']
    url_prefix: http://foobar
`)

	// Invalid src_query_args
	f(`
users:
- username: a
  url_map:
  - src_query_args: abc
    url_prefix: http://foobar
`)

	// Invalid src_headers
	f(`
users:
- username: a
  url_map:
  - src_headers: abc
    url_prefix: http://foobar
`)

	// Invalid headers in url_map (missing ':')
	f(`
users:
- username: a
  url_map:
  - src_paths: ['/foobar']
    url_prefix: http://foobar
    headers:
    - foobar
`)
	// Invalid headers in url_map (dictionary instead of array)
	f(`
users:
- username: a
  url_map:
  - src_paths: ['/foobar']
    url_prefix: http://foobar
    headers:
      aaa: bbb
`)
	// Invalid metric label name
	f(`
users:
- username: foo
  url_prefix: http://foo.bar
  metric_labels:
    not-prometheus-compatible: value
`)
	// placeholder in url_prefix
	f(`
users:
- username: foo
  password: bar
  url_prefix: 'http://ahost/{{a_placeholder}}/foobar'
`)
	// placeholder in a header
	f(`
users:
- username: foo
  password: bar
  headers:
  - 'X-Foo: {{a_placeholder}}'
  url_prefix: 'http://ahost'
`)
	// placeholder in url_prefix
	f(`
users:
- username: foo
  password: bar
  url_prefix: 'http://ahost/{{a_placeholder}}/foobar'
`)
	// placeholder in a header in url_map
	f(`
users:
- username: foo
  password: bar
  url_map:
    - src_paths: ["/select/.*"]
      headers:
        - 'X-Foo: {{a_placeholder}}'
      url_prefix: 'http://ahost'
`)

	// placeholder in a header in url_map
	f(`
users:
- username: foo
  password: bar
  url_map:
    - src_paths: ["/select/.*"]
      url_prefix: 'http://ahost/{{a_placeholder}}/foobar'
`)
}

func TestParseAuthConfigSuccess(t *testing.T) {
	f := func(s string, expectedAuthConfig map[string]*UserInfo, expectedUnauthorizedUserConfig *UserInfo) {
		t.Helper()
		ac, err := parseAuthConfig([]byte(s))
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		m, err := parseAuthConfigUsers(ac)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		removeMetrics(m)
		if err := areEqualConfigs(m, expectedAuthConfig); err != nil {
			t.Fatal(err)
		}

		if err := areEqualConfigs(ac.UnauthorizedUser, expectedUnauthorizedUserConfig); err != nil {
			t.Fatal(err)
		}
	}

	insecureSkipVerifyTrue := true

	// Empty config
	f(``, map[string]*UserInfo{}, nil)

	// Empty users
	f(`users: []`, map[string]*UserInfo{}, nil)

	// Single user
	f(`
users:
- username: foo
  password: bar
  url_prefix: http://aaa:343/bbb
  max_concurrent_requests: 5
  tls_insecure_skip_verify: true
`, map[string]*UserInfo{
		getHTTPAuthBasicToken("foo", "bar"): {
			Username:              "foo",
			Password:              "bar",
			URLPrefix:             mustParseURL("http://aaa:343/bbb"),
			MaxConcurrentRequests: 5,
			TLSInsecureSkipVerify: &insecureSkipVerifyTrue,
		},
	}, nil)

	// Single user with auth_token
	f(`
users:
- auth_token: foo
  url_prefix: https://aaa:343/bbb
  max_concurrent_requests: 5
  tls_insecure_skip_verify: true
  tls_server_name: "foo.bar"
  tls_ca_file: "foo/bar"
  tls_cert_file: "foo/baz"
  tls_key_file: "foo/foo"
`, map[string]*UserInfo{
		getHTTPAuthToken("foo"): {
			AuthToken:             "foo",
			URLPrefix:             mustParseURL("https://aaa:343/bbb"),
			MaxConcurrentRequests: 5,
			TLSInsecureSkipVerify: &insecureSkipVerifyTrue,
			TLSServerName:         "foo.bar",
			TLSCAFile:             "foo/bar",
			TLSCertFile:           "foo/baz",
			TLSKeyFile:            "foo/foo",
		},
	}, nil)

	// Multiple url_prefix entries
	insecureSkipVerifyFalse := false
	discoverBackendIPsTrue := true
	f(`
users:
- username: foo
  password: bar
  url_prefix:
  - http://node1:343/bbb
  - http://srv+node2:343/bbb
  tls_insecure_skip_verify: false
  retry_status_codes: [500, 501]
  load_balancing_policy: first_available
  merge_query_args: [foo, bar]
  drop_src_path_prefix_parts: 1
  discover_backend_ips: true
`, map[string]*UserInfo{
		getHTTPAuthBasicToken("foo", "bar"): {
			Username: "foo",
			Password: "bar",
			URLPrefix: mustParseURLs([]string{
				"http://node1:343/bbb",
				"http://srv+node2:343/bbb",
			}),
			TLSInsecureSkipVerify:  &insecureSkipVerifyFalse,
			RetryStatusCodes:       []int{500, 501},
			LoadBalancingPolicy:    "first_available",
			MergeQueryArgs:         []string{"foo", "bar"},
			DropSrcPathPrefixParts: new(1),
			DiscoverBackendIPs:     &discoverBackendIPsTrue,
		},
	}, nil)

	// Multiple users
	f(`
users:
- username: foo
  url_prefix: http://foo
- username: bar
  url_prefix: https://bar/x/
`, map[string]*UserInfo{
		getHTTPAuthBasicToken("foo", ""): {
			Username:  "foo",
			URLPrefix: mustParseURL("http://foo"),
		},
		getHTTPAuthBasicToken("bar", ""): {
			Username:  "bar",
			URLPrefix: mustParseURL("https://bar/x/"),
		},
	}, nil)

	// non-empty URLMap
	sharedUserInfo := &UserInfo{
		BearerToken: "foo",
		URLMaps: []URLMap{
			{
				SrcPaths:  getRegexs([]string{"/api/v1/query", "/api/v1/query_range", "/api/v1/label/[^./]+/.+"}),
				URLPrefix: mustParseURL("http://vmselect/select/0/prometheus"),
			},
			{
				SrcHosts: getRegexs([]string{"foo\\.bar", "baz:1234"}),
				SrcPaths: getRegexs([]string{"/api/v1/write"}),
				SrcQueryArgs: []*QueryArg{
					mustNewQueryArg("foo=b.+ar"),
					mustNewQueryArg("baz=~.*x=y.+"),
				},
				SrcHeaders: []*Header{
					mustNewHeader("'TenantID: 345'"),
				},
				URLPrefix: mustParseURLs([]string{
					"http://vminsert1/insert/0/prometheus",
					"http://vminsert2/insert/0/prometheus",
				}),
				HeadersConf: HeadersConf{
					RequestHeaders: []*Header{
						mustNewHeader("'foo: bar'"),
						mustNewHeader("'xxx:'"),
					},
				},
			},
		},
	}
	f(`
users:
- bearer_token: foo
  url_map:
  - src_paths: ["/api/v1/query","/api/v1/query_range","/api/v1/label/[^./]+/.+"]
    url_prefix: http://vmselect/select/0/prometheus
  - src_paths: ["/api/v1/write"]
    src_hosts: ["foo\\.bar", "baz:1234"]
    src_query_args: ['foo=b.+ar', 'baz=~.*x=y.+']
    src_headers: ['TenantID: 345']
    url_prefix: ["http://vminsert1/insert/0/prometheus","http://vminsert2/insert/0/prometheus"]
    headers:
    - "foo: bar"
    - "xxx:"
`, map[string]*UserInfo{
		getHTTPAuthBearerToken("foo"):    sharedUserInfo,
		getHTTPAuthBasicToken("foo", ""): sharedUserInfo,
	}, nil)

	// Multiple users with the same name - this should work, since these users have different passwords
	f(`
users:
- username: foo-same
  password: baz
  url_prefix: http://foo
- username: foo-same
  password: bar
  url_prefix: https://bar/x
`, map[string]*UserInfo{
		getHTTPAuthBasicToken("foo-same", "baz"): {
			Username:  "foo-same",
			Password:  "baz",
			URLPrefix: mustParseURL("http://foo"),
		},
		getHTTPAuthBasicToken("foo-same", "bar"): {
			Username:  "foo-same",
			Password:  "bar",
			URLPrefix: mustParseURL("https://bar/x"),
		},
	}, nil)

	// with default url
	keepOriginalHost := true
	f(`
users:
- bearer_token: foo
  url_map:
  - src_paths: ["/api/v1/query","/api/v1/query_range","/api/v1/label/[^./]+/.+"]
    url_prefix: http://vmselect/select/0/prometheus
  - src_paths: ["/api/v1/write"]
    url_prefix: ["http://vminsert1/insert/0/prometheus","http://vminsert2/insert/0/prometheus"]
    headers:
    - "foo: bar"
    - "xxx: y"
    keep_original_host: true
    load_balancing_policy: first_available
    merge_query_args: [foo, bar]
  default_url:
  - http://default1/select/0/prometheus
  - http://default2/select/0/prometheus
`, map[string]*UserInfo{
		getHTTPAuthBearerToken("foo"): {
			BearerToken: "foo",
			URLMaps: []URLMap{
				{
					SrcPaths:  getRegexs([]string{"/api/v1/query", "/api/v1/query_range", "/api/v1/label/[^./]+/.+"}),
					URLPrefix: mustParseURL("http://vmselect/select/0/prometheus"),
				},
				{
					SrcPaths: getRegexs([]string{"/api/v1/write"}),
					URLPrefix: mustParseURLs([]string{
						"http://vminsert1/insert/0/prometheus",
						"http://vminsert2/insert/0/prometheus",
					}),
					HeadersConf: HeadersConf{
						RequestHeaders: []*Header{
							mustNewHeader("'foo: bar'"),
							mustNewHeader("'xxx: y'"),
						},
						KeepOriginalHost: &keepOriginalHost,
					},
					LoadBalancingPolicy: "first_available",
					MergeQueryArgs:      []string{"foo", "bar"},
				},
			},
			DefaultURL: mustParseURLs([]string{
				"http://default1/select/0/prometheus",
				"http://default2/select/0/prometheus",
			}),
		},
		getHTTPAuthBasicToken("foo", ""): {
			BearerToken: "foo",
			URLMaps: []URLMap{
				{
					SrcPaths:  getRegexs([]string{"/api/v1/query", "/api/v1/query_range", "/api/v1/label/[^./]+/.+"}),
					URLPrefix: mustParseURL("http://vmselect/select/0/prometheus"),
				},
				{
					SrcPaths: getRegexs([]string{"/api/v1/write"}),
					URLPrefix: mustParseURLs([]string{
						"http://vminsert1/insert/0/prometheus",
						"http://vminsert2/insert/0/prometheus",
					}),
					HeadersConf: HeadersConf{
						RequestHeaders: []*Header{
							mustNewHeader("'foo: bar'"),
							mustNewHeader("'xxx: y'"),
						},
						KeepOriginalHost: &keepOriginalHost,
					},
					LoadBalancingPolicy: "first_available",
					MergeQueryArgs:      []string{"foo", "bar"},
				},
			},
			DefaultURL: mustParseURLs([]string{
				"http://default1/select/0/prometheus",
				"http://default2/select/0/prometheus",
			}),
		},
	}, nil)

	// With metric_labels
	f(`
users:
- username: foo-same
  password: baz
  url_prefix: http://foo
  metric_labels:
    dc: eu
    team: dev
  keep_original_host: true
- username: foo-same
  password: bar
  url_prefix: https://bar/x
  metric_labels:
    backend_env: test
    team: accounting
  headers:
  - "foo: bar"
  response_headers:
  - "Abc: def"
`, map[string]*UserInfo{
		getHTTPAuthBasicToken("foo-same", "baz"): {
			Username:  "foo-same",
			Password:  "baz",
			URLPrefix: mustParseURL("http://foo"),
			MetricLabels: map[string]string{
				"dc":   "eu",
				"team": "dev",
			},
			HeadersConf: HeadersConf{
				KeepOriginalHost: &keepOriginalHost,
			},
		},
		getHTTPAuthBasicToken("foo-same", "bar"): {
			Username:  "foo-same",
			Password:  "bar",
			URLPrefix: mustParseURL("https://bar/x"),
			MetricLabels: map[string]string{
				"backend_env": "test",
				"team":        "accounting",
			},
			HeadersConf: HeadersConf{
				RequestHeaders: []*Header{
					mustNewHeader("'foo: bar'"),
				},
				ResponseHeaders: []*Header{
					mustNewHeader("'Abc: def'"),
				},
			},
		},
	}, nil)

	// unauthorized_user
	f(`
unauthorized_user:
  merge_query_args: [extra_filters]
  url_map:
  - src_paths: ["/select/.+"]
    url_prefix: 'http://victoria-logs:9428/?extra_filters={env="prod"}'
`, nil, &UserInfo{
		MergeQueryArgs: []string{"extra_filters"},
		URLMaps: []URLMap{
			{
				SrcPaths:  getRegexs([]string{"/select/.+"}),
				URLPrefix: mustParseURL(`http://victoria-logs:9428/?extra_filters={env="prod"}`),
			},
		},
	})

	// skip user info with jwt, it is parsed by parseJWTUsers
	f(`
users:
- username: foo
  password: bar
  url_prefix: http://aaa:343/bbb
- jwt: {skip_verify: true}
  url_prefix: http://aaa:343/bbb
`, map[string]*UserInfo{
		getHTTPAuthBasicToken("foo", "bar"): {
			Username:  "foo",
			Password:  "bar",
			URLPrefix: mustParseURL("http://aaa:343/bbb"),
		},
	}, nil)

	// Multiple users with access logs enabled
	f(`
users:
- username: foo
  url_prefix: http://foo
  access_log: {}
- username: bar
  url_prefix: https://bar/x/
  access_log:
    filters:
      skip_status_codes: [404]
`, map[string]*UserInfo{
		getHTTPAuthBasicToken("foo", ""): {
			Username:  "foo",
			URLPrefix: mustParseURL("http://foo"),
			AccessLog: &AccessLog{},
		},
		getHTTPAuthBasicToken("bar", ""): {
			Username:  "bar",
			URLPrefix: mustParseURL("https://bar/x/"),
			AccessLog: &AccessLog{Filters: &AccessLogFilters{SkipStatusCodes: []int{404}}},
		},
	}, nil)

}

func TestParseAuthConfigPassesTLSVerificationConfig(t *testing.T) {
	c := `
users:
- username: foo
  password: bar
  url_prefix: https://aaa/bbb
  max_concurrent_requests: 5
  tls_insecure_skip_verify: true

unauthorized_user:
  url_prefix: http://aaa:343/bbb
  max_concurrent_requests: 5
  tls_insecure_skip_verify: false
`

	ac, err := parseAuthConfig([]byte(c))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	m, err := parseAuthConfigUsers(ac)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	ui := m[getHTTPAuthBasicToken("foo", "bar")]
	if !isSetBool(ui.TLSInsecureSkipVerify, true) {
		t.Fatalf("unexpected TLSInsecureSkipVerify value for user foo")
	}

	if !isSetBool(ac.UnauthorizedUser.TLSInsecureSkipVerify, false) {
		t.Fatalf("unexpected TLSInsecureSkipVerify value for unauthorized_user")
	}
}

func TestUserInfoGetMetricLabels(t *testing.T) {
	t.Run("empty-labels", func(t *testing.T) {
		ui := &UserInfo{
			Username: "user1",
		}
		labels, err := ui.getMetricLabels()
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		labelsExpected := `{username="user1"}`
		if labels != labelsExpected {
			t.Fatalf("unexpected labels; got %s; want %s", labels, labelsExpected)
		}
	})
	t.Run("non-empty-username", func(t *testing.T) {
		ui := &UserInfo{
			Username: "user1",
			MetricLabels: map[string]string{
				"env":        "prod",
				"datacenter": "dc1",
			},
		}
		labels, err := ui.getMetricLabels()
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		labelsExpected := `{datacenter="dc1",env="prod",username="user1"}`
		if labels != labelsExpected {
			t.Fatalf("unexpected labels; got %s; want %s", labels, labelsExpected)
		}
	})
	t.Run("non-empty-name", func(t *testing.T) {
		ui := &UserInfo{
			Name:        "user1",
			BearerToken: "abc",
			MetricLabels: map[string]string{
				"env":        "prod",
				"datacenter": "dc1",
			},
		}
		labels, err := ui.getMetricLabels()
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		labelsExpected := `{datacenter="dc1",env="prod",username="user1"}`
		if labels != labelsExpected {
			t.Fatalf("unexpected labels; got %s; want %s", labels, labelsExpected)
		}
	})
	t.Run("non-empty-bearer-token", func(t *testing.T) {
		ui := &UserInfo{
			BearerToken: "abc",
			MetricLabels: map[string]string{
				"env":        "prod",
				"datacenter": "dc1",
			},
		}
		labels, err := ui.getMetricLabels()
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		labelsExpected := `{datacenter="dc1",env="prod",username="bearer_token:hash:44BC2CF5AD770999"}`
		if labels != labelsExpected {
			t.Fatalf("unexpected labels; got %s; want %s", labels, labelsExpected)
		}
	})
	t.Run("invalid-label", func(t *testing.T) {
		ui := &UserInfo{
			Username: "foo",
			MetricLabels: map[string]string{
				",{": "aaaa",
			},
		}
		_, err := ui.getMetricLabels()
		if err == nil {
			t.Fatalf("expecting non-nil error")
		}
	})
}

func isSetBool(boolP *bool, expectedValue bool) bool {
	if boolP == nil {
		return false
	}
	return *boolP == expectedValue
}

func TestGetLeastLoadedBackendURL(t *testing.T) {
	up := mustParseURLs([]string{
		"http://node1:343",
		"http://node2:343",
		"http://node3:343",
	})
	up.loadBalancingPolicy = "least_loaded"

	pbus := up.bus.Load()
	bus := pbus.groups[0].bus

	fn := func(ns ...int) {
		t.Helper()

		for i, b := range bus {
			got := int(b.concurrentRequests.Load())
			exp := ns[i]
			if got != exp {
				t.Fatalf("expected %q to have %d concurrent requests; got %d instead", b.url, exp, got)
			}
		}
	}

	up.getBackendURL()
	fn(1, 0, 0)

	up.getBackendURL()
	fn(1, 1, 0)

	up.getBackendURL()
	fn(1, 1, 1)

	bus[1].put()
	bus[2].put()
	fn(1, 0, 0)

	up.getBackendURL()
	fn(1, 1, 0)

	bus[1].put()
	up.getBackendURL()
	fn(1, 0, 1)

	up.getBackendURL()
	up.getBackendURL()
	fn(1, 1, 2)

	bus[0].concurrentRequests.Add(2)
	bus[2].concurrentRequests.Add(2)
	fn(3, 1, 4)

	up.getBackendURL()
	fn(3, 2, 4)

	up.getBackendURL()
	fn(3, 3, 4)

	up.getBackendURL()
	fn(4, 3, 4)

	up.getBackendURL()
	fn(4, 4, 4)

	bus[0].put()
	bus[2].put()

	up.getBackendURL()
	fn(3, 4, 4)

	up.getBackendURL()
	fn(4, 4, 4)
}

func TestBrokenBackend(t *testing.T) {
	up := mustParseURLs([]string{
		"http://node1:343",
		"http://node2:343",
		"http://node3:343",
	})
	up.loadBalancingPolicy = "least_loaded"
	pbus := up.bus.Load()
	bus := pbus.groups[0].bus

	// explicitly mark one of the backends as broken
	bus[1].setBroken()

	// broken backend should never return while there are healthy backends
	for range int(1e3) {
		b := up.getBackendURL()
		if b.isBroken() {
			t.Fatalf("unexpected broken backend %q", b.url)
		}
	}
}

func TestDiscoverBackendIPsWithIPV6(t *testing.T) {
	f := func(actualUrl, expectedUrl string) {
		t.Helper()
		up := mustParseURL(actualUrl)
		up.discoverBackendIPs = true
		up.loadBalancingPolicy = "least_loaded"

		up.discoverBackendAddrsIfNeeded()
		pbus := up.bus.Load()
		bus := pbus.groups[0].bus

		if len(bus) != 1 {
			t.Fatalf("expected url list to be of size 1; got %d instead", len(bus))
		}

		got := bus[0].url.Host
		if got != expectedUrl {
			t.Fatalf(`expected url to be %q; got %q instead`, expectedUrl, bus[0].url.Host)
		}
	}

	// Discover backendURL with SRV hostnames
	customResolver := &fakeResolver{
		Resolver: &net.Resolver{},
		// SRV records must return hostname
		// not an IP address
		lookupSRVResults: map[string][]*net.SRV{
			"_vmselect._tcp.selectwithport.": {
				{
					Target: "vmselect.local",
					Port:   8481,
				},
			},
			"_vmselect._tcp.selectwoport.": {
				{
					Target: "vmselect.local",
				},
			},
		},
		lookupIPAddrResults: map[string][]net.IPAddr{
			"vminsert.local": {
				{
					IP: net.ParseIP("10.0.10.13"),
				},
			},
			"ipv6.vminsert.local": {
				{
					IP: net.ParseIP("2607:f8b0:400a:80b::200e"),
				},
			},
		},
	}
	origResolver := netutil.Resolver
	netutil.Resolver = customResolver
	defer func() {
		netutil.Resolver = origResolver
	}()
	f("http://srv+_vmselect._tcp.selectwithport.:8080", "vmselect.local:8080")
	f("http://srv+_vmselect._tcp.selectwithport.:", "vmselect.local:8481")
	f("http://srv+_vmselect._tcp.selectwoport.:8080", "vmselect.local:8080")
	f("http://srv+_vmselect._tcp.selectwoport.", "vmselect.local:")

	f("http://vminsert.local:8080", "10.0.10.13:8080")
	f("http://vminsert.local", "10.0.10.13:")
	f("http://ipv6.vminsert.local:8080", "[2607:f8b0:400a:80b::200e]:8080")
	f("http://ipv6.vminsert.local", "[2607:f8b0:400a:80b::200e]:")

}

func TestAreEqualBackendURLGroups(t *testing.T) {
	newGroup := func(hosts ...string) *backendURLGroup {
		g := &backendURLGroup{}
		for _, h := range hosts {
			g.bus = append(g.bus, &backendURL{url: &url.URL{Host: h}})
		}
		return g
	}

	f := func(a, b []*backendURLGroup, expected bool) {
		t.Helper()
		if got := areEqualBackendURLGroups(a, b); got != expected {
			t.Fatalf("unexpected result; got %v; want %v", got, expected)
		}
	}

	// identical grouping
	f(
		[]*backendURLGroup{newGroup("10.0.0.1", "10.0.0.2"), newGroup("10.0.0.3")},
		[]*backendURLGroup{newGroup("10.0.0.1", "10.0.0.2"), newGroup("10.0.0.3")},
		true,
	)

	// different number of groups
	f(
		[]*backendURLGroup{newGroup("10.0.0.1")},
		[]*backendURLGroup{newGroup("10.0.0.1"), newGroup("10.0.0.2")},
		false,
	)

	// the flattened address sequence is unchanged, but an address moved across the group boundary
	f(
		[]*backendURLGroup{newGroup("10.0.0.1", "10.0.0.2"), newGroup("10.0.0.3")},
		[]*backendURLGroup{newGroup("10.0.0.1"), newGroup("10.0.0.2", "10.0.0.3")},
		false,
	)

	// genuinely different content
	f(
		[]*backendURLGroup{newGroup("10.0.0.1")},
		[]*backendURLGroup{newGroup("10.0.0.9")},
		false,
	)
}

func TestDiscoverBackendAddrsIfNeededDetectsGroupBoundaryShift(t *testing.T) {
	customResolver := &fakeResolver{
		Resolver: &net.Resolver{},
		lookupIPAddrResults: map[string][]net.IPAddr{
			"zonea": {
				{IP: net.ParseIP("10.0.0.1")},
				{IP: net.ParseIP("10.0.0.2")},
			},
			"zoneb": {
				{IP: net.ParseIP("10.0.0.3")},
			},
		},
	}
	origResolver := netutil.Resolver
	netutil.Resolver = customResolver
	defer func() {
		netutil.Resolver = origResolver
	}()

	up := mustParseURLs([]string{"http://zonea", "http://zoneb"})
	up.discoverBackendIPs = true

	up.discoverBackendAddrsIfNeeded()
	bus := up.bus.Load()
	if len(bus.groups) != 2 || len(bus.groups[0].bus) != 2 || len(bus.groups[1].bus) != 1 {
		t.Fatalf("unexpected initial grouping: zonea=%d zoneb=%d", len(bus.groups[0].bus), len(bus.groups[1].bus))
	}

	// Simulate 10.0.0.2 moving from zonea to zoneb. The flattened address sequence
	// stays [10.0.0.1, 10.0.0.2, 10.0.0.3], but the group boundaries shift, so the
	// rediscovery must still be picked up.
	customResolver.lookupIPAddrResults["zonea"] = []net.IPAddr{
		{IP: net.ParseIP("10.0.0.1")},
	}
	customResolver.lookupIPAddrResults["zoneb"] = []net.IPAddr{
		{IP: net.ParseIP("10.0.0.2")},
		{IP: net.ParseIP("10.0.0.3")},
	}
	up.nextDiscoveryDeadline.Store(0)
	up.discoverBackendAddrsIfNeeded()

	bus = up.bus.Load()
	if len(bus.groups) != 2 {
		t.Fatalf("unexpected groups count after rediscovery: %d", len(bus.groups))
	}
	if len(bus.groups[0].bus) != 1 || bus.groups[0].bus[0].url.Host != "10.0.0.1:" {
		t.Fatalf("unexpected zonea group after rediscovery: %v", bus.groups[0].bus)
	}
	if len(bus.groups[1].bus) != 2 {
		t.Fatalf("unexpected zoneb group size after rediscovery; got %d; want 2", len(bus.groups[1].bus))
	}
}

func TestLogRequest(t *testing.T) {
	ui := &UserInfo{AccessLog: &AccessLog{}}

	testOutput := &bytes.Buffer{}
	logger.SetOutputForTests(testOutput)
	defer logger.ResetOutputForTest()

	req, err := http.NewRequest("GET", "http://localhost:8080/select/0/prometheus", nil)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	f := func(user string, status int, duration time.Duration, expectedLog string) {
		t.Helper()

		testOutput.Reset()
		ui.logRequest(req, user, status, duration)

		got := testOutput.String()
		if expectedLog == "" && got != "" {
			t.Fatalf("expected empty log, got %q", got)
		}
		if !strings.Contains(got, expectedLog) {
			t.Fatalf("output \n%q \nshould contain \n%q", testOutput.String(), expectedLog)
		}
	}

	f("foo", 200, 10*time.Millisecond, `access_log request_host="localhost:8080" request_uri="" status_code=200 remote_addr="" user_agent="" referer="" duration_ms=10 username="foo"`)
	f("foo", 404, time.Second, `access_log request_host="localhost:8080" request_uri="" status_code=404 remote_addr="" user_agent="" referer="" duration_ms=1000 username="foo"`)

	ui.AccessLog.Filters = &AccessLogFilters{SkipStatusCodes: []int{200}}
	f("foo", 200, 10*time.Millisecond, ``)
	f("foo", 404, 10*time.Millisecond, `access_log request_host="localhost:8080" request_uri="" status_code=404 remote_addr="" user_agent="" referer="" duration_ms=10 username="foo"`)
}

func TestGetFirstAvailableBackend(t *testing.T) {
	f := func(broken []bool, expectedIdx int) {
		t.Helper()
		bus := make([]*backendURL, len(broken))
		for i := range broken {
			bus[i] = &backendURL{
				url: &url.URL{Host: fmt.Sprintf("server-%d", i)},
			}
			bus[i].broken.Store(broken[i])
		}
		g := &backendURLGroup{bus: bus}
		bu := g.getFirstAvailable()
		if bu == nil {
			t.Fatalf("unexpected nil backend")
		}
		if bu.url.Host != fmt.Sprintf("server-%d", expectedIdx) {
			t.Fatalf("unexpected backend, expected server-%d, got %s", expectedIdx, bu.url.Host)
		}
	}

	f([]bool{false, false, false}, 0)
	f([]bool{true, true, false}, 2)
	// all backend are broken, then return the first one.
	f([]bool{true, true, true}, 0)
	f([]bool{true}, 0)

}

func newTestGroup(broken ...bool) *backendURLGroup {
	ctx, cancel := context.WithCancel(context.Background())
	bhc := &backendHealthCheck{
		ctx:    ctx,
		cancel: cancel,
	}
	g := &backendURLGroup{
		bus: make([]*backendURL, len(broken)),
	}
	for i, b := range broken {
		g.bus[i] = &backendURL{
			url: &url.URL{Host: fmt.Sprintf("target-%d", i)},
			bhc: bhc,
		}
		g.bus[i].broken.Store(b)
	}
	return g
}

func TestGetFirstAvailableGroup(t *testing.T) {
	// the first group is available
	bus := &backendURLs{groups: []*backendURLGroup{newTestGroup(false), newTestGroup(false)}}
	if g := bus.getFirstAvailable(); g != bus.groups[0] {
		t.Fatalf("expecting the first group to be returned")
	}

	// the first group is fully broken - falls back to the second one
	bus = &backendURLs{groups: []*backendURLGroup{newTestGroup(true), newTestGroup(false)}}
	if g := bus.getFirstAvailable(); g != bus.groups[1] {
		t.Fatalf("expecting the second group to be returned")
	}

	// the first group has a non-broken target - it is still considered available
	bus = &backendURLs{groups: []*backendURLGroup{newTestGroup(true, false), newTestGroup(false)}}
	if g := bus.getFirstAvailable(); g != bus.groups[0] {
		t.Fatalf("expecting the first group to be returned, since it has a non-broken target")
	}

	// all groups are fully broken - the first one is returned
	bus = &backendURLs{groups: []*backendURLGroup{newTestGroup(true), newTestGroup(true)}}
	if g := bus.getFirstAvailable(); g != bus.groups[0] {
		t.Fatalf("expecting the first group to be returned when all groups are broken")
	}
}

func TestGetLeastLoadedGroup(t *testing.T) {
	g0 := newTestGroup(false)
	g1 := newTestGroup(false)
	var n atomic.Uint32
	bus := &backendURLs{groups: []*backendURLGroup{g0, g1}, n: &n}

	// both groups are idle - the first one is picked
	if g := bus.getLeastLoaded(); g != g0 {
		t.Fatalf("expecting g0 to be returned when all groups are idle")
	}

	// g0 becomes more loaded than g1 - g1 must be picked
	g0.bus[0].concurrentRequests.Add(5)
	if g := bus.getLeastLoaded(); g != g1 {
		t.Fatalf("expecting g1 to be returned when it is less loaded than g0")
	}

	// g1 is broken - g0 must be picked despite being more loaded
	g1.bus[0].setBroken()
	if g := bus.getLeastLoaded(); g != g0 {
		t.Fatalf("expecting g0 to be returned when g1 is broken")
	}

	// all groups are broken - the first one is returned
	g0.bus[0].setBroken()
	if g := bus.getLeastLoaded(); g != g0 {
		t.Fatalf("expecting g0 to be returned when all groups are broken")
	}
}

func TestGetBackendURLTwoTier(t *testing.T) {
	// Simulates two backends (busOriginal entries), each expanded into two discovered targets.
	up := &URLPrefix{}
	up.backendGroupCounters = make([]atomic.Uint32, 2)
	bus := newBackendURLs(&up.n)
	bus.addGroup([]*url.URL{{Host: "g0-a"}, {Host: "g0-b"}}, &up.backendGroupCounters[0])
	bus.addGroup([]*url.URL{{Host: "g1-a"}, {Host: "g1-b"}}, &up.backendGroupCounters[1])

	up.bus.Store(bus)
	up.loadBalancingPolicy = "first_available"
	up.backendLoadBalancingPolicy = "first_available"

	if n := up.getBackendsCount(); n != 4 {
		t.Fatalf("unexpected backends count; got %d; want 4", n)
	}

	// Both policies are first_available, so vmauth must always pick group0's first target.
	for range 5 {
		bu := up.getBackendURL()
		if bu.url.Host != "g0-a" {
			t.Fatalf("unexpected target; got %q; want g0-a", bu.url.Host)
		}
		bu.put()
	}

	// Mark group0's first target broken - the backend-level policy falls back to g0-b,
	// while the top-level group selection still prefers group0, since it has a non-broken target.
	bus.groups[0].bus[0].setBroken()
	bu := up.getBackendURL()
	if bu.url.Host != "g0-b" {
		t.Fatalf("unexpected target; got %q; want g0-b", bu.url.Host)
	}
	bu.put()

	// Mark group0 fully broken - the top-level selection falls back to group1.
	bus.groups[0].bus[1].setBroken()
	bu = up.getBackendURL()
	if bu.url.Host != "g1-a" {
		t.Fatalf("unexpected target; got %q; want g1-a", bu.url.Host)
	}
	bu.put()
}

func TestInitURLsBackendLoadBalancingPolicy(t *testing.T) {
	f := func(ui *UserInfo, expectedLBP, expectedBLBP string) {
		t.Helper()

		if err := ui.initURLs(); err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		up := ui.URLPrefix
		if up == nil {
			up = ui.URLMaps[0].URLPrefix
		}
		if up.loadBalancingPolicy != expectedLBP {
			t.Fatalf("unexpected loadBalancingPolicy; got %q; want %q", up.loadBalancingPolicy, expectedLBP)
		}
		if up.backendLoadBalancingPolicy != expectedBLBP {
			t.Fatalf("unexpected backendLoadBalancingPolicy; got %q; want %q", up.backendLoadBalancingPolicy, expectedBLBP)
		}
	}

	// Nothing set - both default to least_loaded.
	f(&UserInfo{
		URLPrefix: mustParseURL("http://foo.bar"),
	}, "least_loaded", "least_loaded")

	// load_balancing_policy is set, backend_load_balancing_policy is not - it inherits load_balancing_policy.
	f(&UserInfo{
		URLPrefix:           mustParseURL("http://foo.bar"),
		LoadBalancingPolicy: "first_available",
	}, "first_available", "first_available")

	// Both are explicitly set to different values.
	f(&UserInfo{
		URLPrefix:                  mustParseURL("http://foo.bar"),
		LoadBalancingPolicy:        "first_available",
		BackendLoadBalancingPolicy: "least_loaded",
	}, "first_available", "least_loaded")

	// url_map inherits backend_load_balancing_policy from its own effective load_balancing_policy.
	f(&UserInfo{
		LoadBalancingPolicy: "first_available",
		URLMaps: []URLMap{
			{
				SrcPaths:  getRegexs([]string{"/foo"}),
				URLPrefix: mustParseURL("http://foo.bar"),
			},
		},
	}, "first_available", "first_available")

	// url_map overrides backend_load_balancing_policy explicitly.
	f(&UserInfo{
		LoadBalancingPolicy: "first_available",
		URLMaps: []URLMap{
			{
				SrcPaths:                   getRegexs([]string{"/foo"}),
				URLPrefix:                  mustParseURL("http://foo.bar"),
				BackendLoadBalancingPolicy: "least_loaded",
			},
		},
	}, "first_available", "least_loaded")
}

func TestInitURLsBackendLoadBalancingPolicyInvalid(t *testing.T) {
	ui := &UserInfo{
		URLPrefix:                  mustParseURL("http://foo.bar"),
		BackendLoadBalancingPolicy: "bogus",
	}
	if err := ui.initURLs(); err == nil {
		t.Fatalf("expecting non-nil error for invalid backend_load_balancing_policy")
	}
}

func getRegexs(paths []string) []*Regex {
	var sps []*Regex
	for _, path := range paths {
		sps = append(sps, mustNewRegex(path))
	}
	return sps
}

func removeMetrics(m map[string]*UserInfo) {
	for _, info := range m {
		info.requests = nil
	}
}

func areEqualConfigs(a, b any) error {
	aData, err := yaml.Marshal(a)
	if err != nil {
		return fmt.Errorf("cannot marshal a: %w", err)
	}
	bData, err := yaml.Marshal(b)
	if err != nil {
		return fmt.Errorf("cannot marshal b: %w", err)
	}
	if !bytes.Equal(aData, bData) {
		return fmt.Errorf("unexpected configs;\ngot\n%s\nwant\n%s", aData, bData)
	}
	return nil
}

func mustParseURL(u string) *URLPrefix {
	return mustParseURLs([]string{u})
}

func mustParseURLs(us []string) *URLPrefix {
	urls := make([]*url.URL, len(us))
	for i, u := range us {
		pu, err := url.Parse(u)
		if err != nil {
			panic(fmt.Errorf("BUG: cannot parse %q: %w", u, err))
		}
		urls[i] = pu
	}
	up := &URLPrefix{}
	if len(us) == 1 {
		up.vOriginal = us[0]
	} else {
		up.vOriginal = us
	}
	up.busOriginal = urls
	up.backendGroupCounters = make([]atomic.Uint32, len(us))
	bus := newBackendURLs(&up.n)
	bus.addGroup(urls, &up.backendGroupCounters[0])
	up.bus.Store(bus)
	return up
}

func mustNewRegex(s string) *Regex {
	var re Regex
	if err := yaml.Unmarshal([]byte(s), &re); err != nil {
		logger.Panicf("cannot unmarshal regex %q: %s", s, err)
	}
	return &re
}

func mustNewQueryArg(s string) *QueryArg {
	var qa QueryArg
	if err := yaml.Unmarshal([]byte(s), &qa); err != nil {
		logger.Panicf("cannot unmarshal query arg filter %q: %s", s, err)
	}
	return &qa
}

func mustNewHeader(s string) *Header {
	var h Header
	if err := yaml.Unmarshal([]byte(s), &h); err != nil {
		logger.Panicf("cannot unmarshal header filter %q: %s", s, err)
	}
	return &h
}
