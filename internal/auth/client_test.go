package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/basecamp/basecamp-sdk/go/pkg/basecamp"
	"github.com/basecamp/basecamp-sdk/go/pkg/basecamp/oauth"
	surfguard "github.com/basecamp/surfguard/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/basecamp/basecamp-cli/internal/config"
	"github.com/basecamp/basecamp-cli/internal/output"
)

// clearProxyEnv empties every proxy variable httpproxy reads so ambient
// developer/CI configuration cannot leak into lane construction. Tests that
// need a proxy set their own values on top.
func clearProxyEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "REQUEST_METHOD", oauthUseProxyEnv} {
		t.Setenv(v, "")
	}
}

// laneManager builds a Manager with no injected client (the production
// configuration) so the per-provenance lanes are exercised for real.
func laneManager(t *testing.T, baseURL string) *Manager {
	t.Helper()
	cfg := config.Default()
	cfg.BaseURL = baseURL
	return &Manager{
		cfg:   cfg,
		store: newTestStore(t, t.TempDir()),
	}
}

// doGet issues a context-carrying GET on the given client — the lane tests'
// one HTTP verb — keeping the request path identical across cases.
func doGet(t *testing.T, client *http.Client, rawURL string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	require.NoError(t, err)
	return client.Do(req)
}

// TestCheckAuthClientRedirect_StopsLoop verifies the lane clients' redirect
// guard caps idempotent (GET) follows at Go's default 10-hop limit. A looping
// endpoint would otherwise spin until the 30s client timeout instead of
// failing fast, since the guard only blocks non-GET/HEAD redirects.
func TestCheckAuthClientRedirect_StopsLoop(t *testing.T) {
	var hops atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops.Add(1)
		http.Redirect(w, r, "/", http.StatusFound)
	}))
	defer srv.Close()

	client := &http.Client{CheckRedirect: checkAuthClientRedirect, Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err, "redirect loop must fail rather than hang")
	assert.Contains(t, err.Error(), "stopped after 10 redirects")
	assert.LessOrEqual(t, hops.Load(), int32(11), "client must give up around the 10-redirect cap")
}

// TestCheckAuthClientRedirect_BlocksCredentialPOST verifies a non-GET/HEAD
// initial request never follows a redirect: the guard returns
// ErrUseLastResponse so a credential-bearing POST body is not replayed to the
// redirect target.
func TestCheckAuthClientRedirect_BlocksCredentialPOST(t *testing.T) {
	post := &http.Request{Method: http.MethodPost}
	err := checkAuthClientRedirect(nil, []*http.Request{post})
	assert.ErrorIs(t, err, http.ErrUseLastResponse)
}

// TestOAuthEndpointPolicy_LoopbackDerivation drives the policy derivation
// through hostutil's host handling: loopback admission must key off the
// lowercased host of a parsed URL, for every spelling of "local".
func TestOAuthEndpointPolicy_LoopbackDerivation(t *testing.T) {
	loopback := netip.MustParseAddr("127.0.0.1")

	cases := []struct {
		name          string
		anchor        string
		wantErr       bool
		allowLoopback bool
	}{
		{"plain localhost", "http://localhost:3001", false, true},
		{"mixed-case localhost", "http://LocalHost:3001", false, true},
		{"dot-localhost subdomain", "http://3.basecamp.localhost:3001", false, true},
		{"uppercase dot-localhost", "http://3.Basecamp.LOCALHOST:3001", false, true},
		{"IPv4 loopback", "http://127.0.0.1:3000", false, true},
		{"bracketed IPv6 loopback", "http://[::1]:3000", false, true},
		{"userinfo does not confuse host extraction", "http://user:pass@localhost:3001", false, true},
		{"production host", "https://3.basecampapi.com", false, false},
		{"production launchpad", "https://launchpad.37signals.com", false, false},
		{"userinfo on production host", "https://user@3.basecampapi.com", false, false},
		{"malformed URL", "http://[::1", true, false},
		{"relative URL", "/not/absolute", true, false},
		{"empty", "", true, false},
		{"opaque form", "https:foo", true, false},
		{"hostless", "https://", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := oauthEndpointPolicy(tc.anchor, "base URL")
			if tc.wantErr {
				require.Error(t, err)
				if tc.anchor != "" {
					assert.NotContains(t, err.Error(), tc.anchor, "errors must not echo the anchor value")
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, !tc.allowLoopback, policy.Blocked(loopback),
				"loopback admission for %q", tc.anchor)
		})
	}
}

// TestBC5Lane_LoopbackFollowsBaseURL proves the derived policy at the CLIENT
// level, not just the helper: a local base URL admits loopback OAuth traffic
// on the BC5 lane, a production base URL refuses it before any connection.
func TestBC5Lane_LoopbackFollowsBaseURL(t *testing.T) {
	clearProxyEnv(t)

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{}`)
	}))
	defer srv.Close()

	t.Run("local base URL admits loopback", func(t *testing.T) {
		m := laneManager(t, srv.URL)
		client, err := m.bc5Client()
		require.NoError(t, err)
		resp, err := doGet(t, client, srv.URL)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, int32(1), hits.Load())
	})

	t.Run("production base URL refuses loopback", func(t *testing.T) {
		hits.Store(0)
		m := laneManager(t, "https://3.basecampapi.com")
		client, err := m.bc5Client()
		require.NoError(t, err)
		resp, err := doGet(t, client, srv.URL)
		if resp != nil {
			_ = resp.Body.Close()
		}
		require.Error(t, err)
		assert.ErrorIs(t, err, surfguard.ErrBlocked)
		assert.Zero(t, hits.Load(), "the refused target must never be dialed")
	})
}

// TestMixedProvenance_LaunchpadAllowanceDoesNotLeakToBC5 is the negative test
// for the per-lane split: a localhost BASECAMP_LAUNCHPAD_URL grants loopback
// to the LAUNCHPAD lane only. Production BC5 metadata naming a loopback
// endpoint must still be refused — one shared loopback-enabled client would
// have inherited the unrelated Launchpad allowance.
func TestMixedProvenance_LaunchpadAllowanceDoesNotLeakToBC5(t *testing.T) {
	clearProxyEnv(t)

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{}`)
	}))
	defer srv.Close()

	t.Setenv("BASECAMP_LAUNCHPAD_URL", srv.URL)
	m := laneManager(t, "https://3.basecampapi.com")

	bc5, err := m.bc5Client()
	require.NoError(t, err)
	resp, err := doGet(t, bc5, srv.URL)
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err, "the BC5 lane must not inherit the Launchpad loopback allowance")
	assert.ErrorIs(t, err, surfguard.ErrBlocked)
	assert.Zero(t, hits.Load())

	lp, err := m.launchpadClient()
	require.NoError(t, err)
	resp, err = doGet(t, lp, srv.URL)
	require.NoError(t, err, "the Launchpad lane earned loopback from its own anchor")
	_ = resp.Body.Close()
	assert.Equal(t, int32(1), hits.Load())
}

// TestLaunchpadLane_LazyValidation: a malformed Launchpad override surfaces at
// the operation that needs the lane — Manager construction and BC5-lane use
// stay unaffected.
func TestLaunchpadLane_LazyValidation(t *testing.T) {
	clearProxyEnv(t)
	// Survives launchpadURL()'s scheme gate (not an http:// URL) but is no
	// lane anchor: relative, so the policy derivation refuses it.
	t.Setenv("BASECAMP_LAUNCHPAD_URL", "not-a-url")

	m := laneManager(t, "https://3.basecampapi.com")
	_, err := m.bc5Client()
	require.NoError(t, err, "the BC5 lane must not depend on the Launchpad anchor")

	_, err = m.launchpadClient()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Launchpad URL")
}

// countingTransport records round trips so tests can prove a sub-transport
// was, or was never, invoked.
type countingTransport struct {
	calls atomic.Int32
	resp  func() (*http.Response, error)
}

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.calls.Add(1)
	if c.resp != nil {
		return c.resp()
	}
	return nil, errors.New("counting transport: no response configured")
}

// TestOAuthTransport_ResolverErrorFailsClosed: a proxy-resolver error refuses
// the request BEFORE either sub-transport runs. A malformed proxy
// configuration must not degrade into egress — guarded or proxied — that the
// operator asked to route elsewhere.
func TestOAuthTransport_ResolverErrorFailsClosed(t *testing.T) {
	guarded := &countingTransport{}
	proxied := &countingTransport{}
	tr := &oauthTransport{
		guarded: guarded,
		proxied: proxied,
		resolve: func(*url.URL) (*url.URL, error) { return nil, errors.New("bad proxy config") },
		optOut:  true,
		warnf:   func(string, ...any) {},
		warned:  map[string]bool{},
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://public.example/token", nil)
	require.NoError(t, err)
	resp, err := tr.RoundTrip(req)
	require.Nil(t, resp)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "proxy configuration error")
	assert.Zero(t, guarded.calls.Load(), "guarded sub-transport must not run on a resolver error")
	assert.Zero(t, proxied.calls.Load(), "proxied sub-transport must not run on a resolver error")
}

// TestOAuthTransport_CGIRefusesHTTPProxy: in a CGI environment
// (REQUEST_METHOD set) httpproxy refuses to honor HTTP_PROXY, as an ERROR —
// which our fail-closed branch turns into a refused request rather than
// silent egress. This is the one resolver-error path the real environment
// can produce.
func TestOAuthTransport_CGIRefusesHTTPProxy(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTP_PROXY", "http://proxy.corp.example:3128")
	t.Setenv("REQUEST_METHOD", "GET")

	var warnings []string
	m := laneManager(t, "https://3.basecampapi.com")
	m.Warnf = func(format string, args ...any) { warnings = append(warnings, fmt.Sprintf(format, args...)) }

	client, err := m.bc5Client()
	require.NoError(t, err)
	resp, err := doGet(t, client, "http://203.0.113.5/token")
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err)
	assert.Contains(t, err.Error(), "proxy configuration error")
	assert.Empty(t, warnings, "a refused request is not a proxy-ignored warning")
}

// TestOAuthTransport_MalformedProxyValueStaysEnforced documents httpproxy's
// handling of an unparsable proxy URL: config.init drops it, so the resolver
// reports no proxy and the request stays on the GUARDED direct transport.
// Enforcement is never lost to a broken proxy value — there is no unguarded
// fallback to reach.
func TestOAuthTransport_MalformedProxyValueStaysEnforced(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTP_PROXY", "http://[::1%25en0:8080") // unparsable both raw and http://-prefixed

	m := laneManager(t, "https://3.basecampapi.com")
	client, err := m.bc5Client()
	require.NoError(t, err)
	// 203.0.113.5 is TEST-NET-3 documentation space: IANA special-purpose,
	// refused by the default policy before any socket opens.
	resp, err := doGet(t, client, "http://203.0.113.5/token")
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err)
	assert.ErrorIs(t, err, surfguard.ErrBlocked, "the guarded transport must still enforce")
}

// TestProtectedMode_WarnsWhenProxyIgnored: in the default mode the policy
// applies unconditionally; a proxy the environment would have used for an
// OAuth request is ignored WITH a warning, once per endpoint, and behavior
// stays enforced.
func TestProtectedMode_WarnsWhenProxyIgnored(t *testing.T) {
	for _, envVar := range []string{"HTTP_PROXY", "http_proxy"} {
		t.Run(envVar, func(t *testing.T) {
			clearProxyEnv(t)
			t.Setenv(envVar, "http://proxy.corp.example:3128")

			var warnings []string
			m := laneManager(t, "https://3.basecampapi.com")
			m.Warnf = func(format string, args ...any) { warnings = append(warnings, fmt.Sprintf(format, args...)) }

			client, err := m.bc5Client()
			require.NoError(t, err)

			// Two requests to the same endpoint: enforcement holds on both
			// (special-purpose space, zero dials), the warning fires once.
			for range 2 {
				resp, reqErr := doGet(t, client, "http://203.0.113.5/token")
				if resp != nil {
					_ = resp.Body.Close()
				}
				require.Error(t, reqErr)
				assert.ErrorIs(t, reqErr, surfguard.ErrBlocked, "protected mode must stay enforced")
			}
			require.Len(t, warnings, 1, "the proxy-ignored warning is deduplicated per endpoint")
			assert.Contains(t, warnings[0], "ignoring proxy")
			assert.Contains(t, warnings[0], oauthUseProxyEnv+"=1")
		})
	}
}

// TestProtectedMode_NoProxyExclusionProducesNoWarning: a host NO_PROXY
// excludes was never going through the proxy, so there is nothing to warn
// about.
func TestProtectedMode_NoProxyExclusionProducesNoWarning(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTP_PROXY", "http://proxy.corp.example:3128")
	t.Setenv("NO_PROXY", "203.0.113.5")

	var warnings []string
	m := laneManager(t, "https://3.basecampapi.com")
	m.Warnf = func(format string, args ...any) { warnings = append(warnings, fmt.Sprintf(format, args...)) }

	client, err := m.bc5Client()
	require.NoError(t, err)
	resp, err := doGet(t, client, "http://203.0.113.5/token")
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err)
	assert.ErrorIs(t, err, surfguard.ErrBlocked)
	assert.Empty(t, warnings)
}

// TestOptOutMode_RoutesThroughProxyWithoutEnforcement: BASECAMP_OAUTH_USE_PROXY=1
// routes a request the resolver assigns to a proxy through that proxy, with
// address enforcement off for exactly that request and the downgrade logged.
// The proxy owns the connection, so the target host is never resolved or
// dialed directly.
func TestOptOutMode_RoutesThroughProxyWithoutEnforcement(t *testing.T) {
	var proxied atomic.Int32
	var sawAbsoluteURI atomic.Bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Add(1)
		// A plain-HTTP proxy request carries the absolute target URI.
		if r.URL.IsAbs() && r.URL.Host == "public.example" {
			sawAbsoluteURI.Store(true)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer proxy.Close()

	clearProxyEnv(t)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv(oauthUseProxyEnv, "1")

	var warnings []string
	m := laneManager(t, "https://3.basecampapi.com")
	m.Warnf = func(format string, args ...any) { warnings = append(warnings, fmt.Sprintf(format, args...)) }

	client, err := m.bc5Client()
	require.NoError(t, err)
	resp, err := doGet(t, client, "http://public.example/token")
	require.NoError(t, err, "the proxy answers; no direct dial happens")
	_ = resp.Body.Close()

	assert.Equal(t, int32(1), proxied.Load())
	assert.True(t, sawAbsoluteURI.Load(), "the request must traverse the proxy, not dial direct")
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "WITHOUT the SSRF address policy")
}

// TestOptOutMode_NoProxyTargetStaysGuarded is the decisive fail-closed
// regression: opt-out mode with a NO_PROXY exclusion covering a private OAuth
// target must NOT fall back to unguarded direct egress — the request rides
// the guarded transport and the address policy refuses it with zero dials.
func TestOptOutMode_NoProxyTargetStaysGuarded(t *testing.T) {
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxied.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer proxy.Close()

	clearProxyEnv(t)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "203.0.113.5")
	t.Setenv(oauthUseProxyEnv, "1")

	m := laneManager(t, "https://3.basecampapi.com")
	client, err := m.bc5Client()
	require.NoError(t, err)
	resp, err := doGet(t, client, "http://203.0.113.5/token")
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err)
	assert.ErrorIs(t, err, surfguard.ErrBlocked, "resolver-nil requests must ride the guarded transport even in opt-out mode")
	assert.Zero(t, proxied.Load())
}

// TestOptOutMode_MalformedValuesAreOffWithWarning: only the exact value "1"
// opts out. Any other non-empty value is treated as off, with a warning, and
// enforcement stays on. Set-but-empty is off too, but silently — see the
// final subtest.
func TestOptOutMode_MalformedValuesAreOffWithWarning(t *testing.T) {
	for _, v := range []string{"yes", "2"} {
		t.Run(fmt.Sprintf("value %q", v), func(t *testing.T) {
			clearProxyEnv(t)
			t.Setenv("HTTP_PROXY", "http://proxy.corp.example:3128")
			t.Setenv(oauthUseProxyEnv, v)

			var warnings []string
			m := laneManager(t, "https://3.basecampapi.com")
			m.Warnf = func(format string, args ...any) { warnings = append(warnings, fmt.Sprintf(format, args...)) }

			client, err := m.bc5Client()
			require.NoError(t, err)
			resp, reqErr := doGet(t, client, "http://203.0.113.5/token")
			if resp != nil {
				_ = resp.Body.Close()
			}
			require.Error(t, reqErr)
			assert.ErrorIs(t, reqErr, surfguard.ErrBlocked, "a malformed opt-out must not disable enforcement")

			require.NotEmpty(t, warnings)
			assert.Contains(t, warnings[0], "is not understood")
		})
	}

	// t.Setenv cannot distinguish set-but-empty from unset for the reader,
	// but os.LookupEnv can — and clearProxyEnv sets "" for every variable,
	// so every test above already runs the set-but-empty case for the
	// OTHER variables. Pin the semantics explicitly: empty means unset here
	// (getEnvAny-style), silently off, because "" is what clearing tooling
	// writes and warning on it would fire for every user of direnv-style
	// scrubbing.
	t.Run(`value ""`, func(t *testing.T) {
		clearProxyEnv(t)

		var warnings []string
		m := laneManager(t, "https://3.basecampapi.com")
		m.Warnf = func(format string, args ...any) { warnings = append(warnings, fmt.Sprintf(format, args...)) }
		_, err := m.bc5Client()
		require.NoError(t, err)
		assert.Empty(t, warnings, "set-but-empty is indistinguishable from cleared; stay silent and off")
	})
}

// TestDiscoverOAuth_LocalIssuerChainFollowsBaseURL is the end-to-end
// provenance test for discovery: a local resource advertising a local issuer
// succeeds under a local base URL (the lane's AllowLoopback covers hop 2 via
// WithIssuerHTTPClient), and the same chain is refused under a production
// base URL.
func TestDiscoverOAuth_LocalIssuerChainFollowsBaseURL(t *testing.T) {
	clearProxyEnv(t)

	var hits atomic.Int32
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"resource":%q,"authorization_servers":[%q]}`, srv.URL, srv.URL)
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"device_authorization_endpoint":%q,"grant_types_supported":["urn:ietf:params:oauth:grant-type:device_code"]}`,
			srv.URL, srv.URL+"/authorize", srv.URL+"/token", srv.URL+"/device")
	})

	t.Run("local base URL: local advertised issuer is admitted", func(t *testing.T) {
		m := laneManager(t, srv.URL)
		d, err := m.discoverOAuth(context.Background(), func(string) {})
		require.NoError(t, err)
		assert.Equal(t, oauthTypeBC5, d.oauthType)
		assert.Equal(t, srv.URL+"/token", d.config.TokenEndpoint)
		assert.Equal(t, int32(2), hits.Load(), "both hops ride the loopback-admitting lane")
	})

	t.Run("production base URL: the same loopback chain is never dialed", func(t *testing.T) {
		// Build the lane under production provenance, THEN point the flow at
		// the loopback chain: the policy travels with the lane, so hop 1 is
		// refused before any connection. The SDK classifies a failed
		// resource fetch as the soft Launchpad fallback — the observable
		// here is that the loopback chain gets ZERO requests and no BC5
		// device flow is selected from it.
		hits.Store(0)
		m := laneManager(t, "https://3.basecampapi.com")
		_, err := m.bc5Client()
		require.NoError(t, err)
		m.cfg.BaseURL = srv.URL
		d, err := m.discoverOAuth(context.Background(), func(string) {})
		require.NoError(t, err)
		assert.Equal(t, oauthTypeLaunchpad, d.oauthType, "a refused resource fetch falls back to Launchpad, never a BC5 flow from the refused chain")
		assert.Zero(t, hits.Load(), "the loopback chain must never be dialed under production provenance")
	})
}

// TestRefreshLocked_PreservesSDKErrorTaxonomy: the CLI boundary used to
// stringify SDK failures into ErrAPI(0). A policy refusal must survive as
// errors.Is(err, surfguard.ErrBlocked) and errors.As(*basecamp.Error), with
// the SDK's code intact, so callers and exit-code mapping see the real
// verdict.
func TestRefreshLocked_PreservesSDKErrorTaxonomy(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("BASECAMP_OAUTH_CLIENT_ID", "")
	t.Setenv("BASECAMP_OAUTH_CLIENT_SECRET", "")

	m := laneManager(t, "https://3.basecampapi.com")
	creds := &Credentials{
		AccessToken:  "stale",
		RefreshToken: "refresh-token",
		OAuthType:    oauthTypeLaunchpad,
		// TEST-NET-3: refused by the Launchpad lane's policy at dial time.
		TokenEndpoint: "https://203.0.113.5/authorization/token",
	}
	require.NoError(t, m.store.Save("https://3.basecampapi.com", creds))

	err := m.refreshLocked(context.Background(), "https://3.basecampapi.com", creds)
	require.Error(t, err)

	assert.ErrorIs(t, err, surfguard.ErrBlocked, "surfguard verdict must survive the CLI boundary")
	var sdkErr *basecamp.Error
	require.ErrorAs(t, err, &sdkErr, "the SDK's typed error must survive the CLI boundary")
	var cliErr *output.Error
	require.ErrorAs(t, err, &cliErr)
	assert.Equal(t, sdkErr.Code, cliErr.Code, "the SDK's code must not be flattened")
	assert.True(t, strings.HasPrefix(cliErr.Message, "token refresh failed: "), "message keeps the operation prefix: %q", cliErr.Message)
}

// TestExchangeCode_PreservesSDKErrorTaxonomy: same contract on the web-flow
// exchange wrap.
func TestExchangeCode_PreservesSDKErrorTaxonomy(t *testing.T) {
	clearProxyEnv(t)

	m := laneManager(t, "https://3.basecampapi.com")
	cfg := &oauth.Config{TokenEndpoint: "https://203.0.113.5/authorization/token"}
	_, err := m.exchangeCode(context.Background(), cfg, "auth-code",
		&ClientCredentials{ClientID: "id", ClientSecret: "secret"},
		&LoginOptions{RedirectURI: defaultRedirectURI})
	require.Error(t, err)

	assert.ErrorIs(t, err, surfguard.ErrBlocked)
	var sdkErr *basecamp.Error
	require.ErrorAs(t, err, &sdkErr)
	var cliErr *output.Error
	require.ErrorAs(t, err, &cliErr)
	assert.Equal(t, sdkErr.Code, cliErr.Code)
	assert.True(t, strings.HasPrefix(cliErr.Message, "token exchange failed: "))
}

// TestRefreshLocked_RedirectStatusSurvives asserts a refused token-endpoint
// redirect reaches the caller as a typed error carrying the 3xx status.
func TestRefreshLocked_RedirectStatusSurvives(t *testing.T) {
	t.Skip("SDK pin predates token-endpoint redirect classification (basecamp-sdk branch harden-token-exchange); un-skip at the next re-pin")
}

// TestRedactedEndpoint_KeepsEscapesAndDropsSecrets: the endpoint comes from
// a discovery document, so decoded control sequences must stay
// percent-encoded, and query/userinfo must not reach the terminal.
func TestRedactedEndpoint_KeepsEscapesAndDropsSecrets(t *testing.T) {
	u, err := url.Parse("https://user:pw@issuer.example/token%1b%5b31m%0ainjected?code=secret#frag")
	require.NoError(t, err)
	got := redactedEndpoint(u)
	assert.Equal(t, "https://issuer.example/token%1b%5b31m%0ainjected", got)
	assert.NotContains(t, got, "\x1b")
	assert.NotContains(t, got, "\n")
}

// TestRedactedProxy_SchemeAndHostOnly: HTTP(S)_PROXY may carry a token as a
// bare username or a query parameter, which url.URL.Redacted preserves.
func TestRedactedProxy_SchemeAndHostOnly(t *testing.T) {
	u, err := url.Parse("http://token123@proxy.corp.example:3128/?key=abc")
	require.NoError(t, err)
	assert.Equal(t, "http://proxy.corp.example:3128", redactedProxy(u))
}

// fixedLookup answers every host with one fixture. An empty family is a
// definitive not-found, the same shape a single-stack name produces.
type fixedLookup struct {
	v4 []netip.Addr
	v6 []netip.Addr
}

func (f fixedLookup) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	switch network {
	case "ip4":
		if len(f.v4) == 0 {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return append([]netip.Addr(nil), f.v4...), nil
	case "ip6":
		if len(f.v6) == 0 {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		return append([]netip.Addr(nil), f.v6...), nil
	default:
		return nil, fmt.Errorf("unexpected lookup network %s", network)
	}
}

func mustAddrs(t *testing.T, raw []string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, 0, len(raw))
	for _, s := range raw {
		addr, err := netip.ParseAddr(s)
		require.NoError(t, err)
		out = append(out, addr)
	}
	return out
}

// TestAllowUnderSpecialUseDoesNotAdmitBenchmarkingRange pins the surfguard
// constraint the carve-out exists because of: Allow does not re-admit a
// prefix the IANA special-use tables refuse, so the issuer policy cannot
// be talked into dialing 198.18.0.1.
func TestAllowUnderSpecialUseDoesNotAdmitBenchmarkingRange(t *testing.T) {
	policy := oauth.DefaultIssuerPolicy().Allow(benchmarkingPrefix)
	assert.True(t, policy.Blocked(netip.MustParseAddr("198.18.0.1")))
	assert.False(t, relaxedBenchmarkPolicy.Blocked(netip.MustParseAddr("198.18.0.1")))
}

// TestLaunchpadAnchor_BenchmarkingPlaceholder is the dial-path carve-out.
// A request whose Launchpad anchor resolves only to 198.18.0.0/15 is
// admitted and the admitted address is what would be dialed. A genuinely
// private answer, a mixed answer, a different host, and a literal
// benchmarking address are refused with surfguard.ErrBlocked and the
// connect seam is never called.
func TestLaunchpadAnchor_BenchmarkingPlaceholder(t *testing.T) {
	cases := []struct {
		name        string
		launchpad   string
		request     string
		v4          []string
		v6          []string
		wantDial    int32
		wantBlocked bool
		wantAddr    string
	}{
		{
			name:     "anchor resolving only to 198.18.0.1 is dialed",
			request:  "https://launchpad.37signals.com/authorization/token",
			v4:       []string{"198.18.0.1"},
			wantDial: 1,
			wantAddr: "tcp4 198.18.0.1:443",
		},
		{
			name:     "last address of the benchmarking range is dialed",
			request:  "https://launchpad.37signals.com/authorization/token",
			v4:       []string{"198.19.255.255"},
			wantDial: 1,
			wantAddr: "tcp4 198.19.255.255:443",
		},
		{
			name:     "both benchmarking answers are dialed",
			request:  "https://launchpad.37signals.com/authorization/token",
			v4:       []string{"198.18.0.1", "198.19.0.5"},
			wantDial: 2,
		},
		{
			name:     "mixed-case anchor is the same host",
			request:  "https://LaunchPad.37signals.com/authorization/token",
			v4:       []string{"198.18.0.1"},
			wantDial: 1,
			wantAddr: "tcp4 198.18.0.1:443",
		},
		{
			name:     "trailing dot is the same host",
			request:  "https://launchpad.37signals.com./authorization/token",
			v4:       []string{"198.18.0.1"},
			wantDial: 1,
			wantAddr: "tcp4 198.18.0.1:443",
		},
		{
			name:     "userinfo does not change the host",
			request:  "https://user:secret@launchpad.37signals.com/authorization/token",
			v4:       []string{"198.18.0.1"},
			wantDial: 1,
			wantAddr: "tcp4 198.18.0.1:443",
		},
		{
			name:      "custom anchor admits its own name",
			launchpad: "https://lp.example.test",
			request:   "https://lp.example.test/authorization/token",
			v4:        []string{"198.18.0.1"},
			wantDial:  1,
			wantAddr:  "tcp4 198.18.0.1:443",
		},
		{
			name:      "custom anchor port is dialed and the host still matches",
			launchpad: "https://lp.example.test:8443",
			request:   "https://lp.example.test:8443/authorization/token",
			v4:        []string{"198.18.0.1"},
			wantDial:  1,
			wantAddr:  "tcp4 198.18.0.1:8443",
		},
		{
			name:        "custom anchor does not admit the default host",
			launchpad:   "https://lp.example.test",
			request:     "https://launchpad.37signals.com/authorization/token",
			v4:          []string{"198.18.0.1"},
			wantBlocked: true,
		},
		{
			name:      "punycode request matches a unicode anchor",
			launchpad: "https://bücher.example",
			request:   "https://xn--bcher-kva.example/token",
			v4:        []string{"198.18.0.1"},
			wantDial:  1,
			wantAddr:  "tcp4 198.18.0.1:443",
		},
		{
			name:        "rfc1918 stays blocked",
			request:     "https://launchpad.37signals.com/authorization/token",
			v4:          []string{"10.0.0.1"},
			wantBlocked: true,
		},
		{
			name:        "192.168 stays blocked",
			request:     "https://launchpad.37signals.com/authorization/token",
			v4:          []string{"192.168.1.1"},
			wantBlocked: true,
		},
		{
			name:        "172.16/12 stays blocked",
			request:     "https://launchpad.37signals.com/authorization/token",
			v4:          []string{"172.16.0.1"},
			wantBlocked: true,
		},
		{
			name:        "loopback stays blocked",
			request:     "https://launchpad.37signals.com/authorization/token",
			v4:          []string{"127.0.0.1"},
			wantBlocked: true,
		},
		{
			name:        "link-local metadata stays blocked",
			request:     "https://launchpad.37signals.com/authorization/token",
			v4:          []string{"169.254.169.254"},
			wantBlocked: true,
		},
		{
			name:        "cgnat stays blocked",
			request:     "https://launchpad.37signals.com/authorization/token",
			v4:          []string{"100.64.0.1"},
			wantBlocked: true,
		},
		{
			name:        "documentation range stays blocked",
			request:     "https://launchpad.37signals.com/authorization/token",
			v4:          []string{"203.0.113.5"},
			wantBlocked: true,
		},
		{
			name:        "test-net-2 stays blocked",
			request:     "https://launchpad.37signals.com/authorization/token",
			v4:          []string{"198.51.100.1"},
			wantBlocked: true,
		},
		{
			name:        "mixed benchmarking and private stays blocked",
			request:     "https://launchpad.37signals.com/authorization/token",
			v4:          []string{"198.18.0.1", "10.0.0.1"},
			wantBlocked: true,
		},
		{
			name:        "mixed benchmarking and documentation ipv6 stays blocked",
			request:     "https://launchpad.37signals.com/authorization/token",
			v4:          []string{"198.18.0.1"},
			v6:          []string{"2001:db8::1"},
			wantBlocked: true,
		},
		{
			name:        "different host resolving to 198.18.0.1 stays blocked",
			request:     "https://evil.example/token",
			v4:          []string{"198.18.0.1"},
			wantBlocked: true,
		},
		{
			name:        "literal benchmarking address stays blocked",
			request:     "https://198.18.0.1/authorization/token",
			v4:          []string{"198.18.0.1"},
			wantBlocked: true,
		},
		{
			name:        "literal anchor does not carve the range out",
			launchpad:   "https://198.18.0.1",
			request:     "https://198.18.0.1/authorization/token",
			v4:          []string{"198.18.0.1"},
			wantBlocked: true,
		},
		{
			name:        "unsupported scheme is refused before dial",
			request:     "ftp://launchpad.37signals.com/token",
			v4:          []string{"198.18.0.1"},
			wantBlocked: true,
		},
		{
			name:        "non-ascii host is refused before dial",
			request:     "https://ex\u009bample.com/token",
			v4:          []string{"198.18.0.1"},
			wantBlocked: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearProxyEnv(t)
			t.Setenv("BASECAMP_LAUNCHPAD_URL", tc.launchpad)

			var dials atomic.Int32
			var dialed []string
			m := laneManager(t, "https://3.basecampapi.com")
			m.launchpadLookup = fixedLookup{v4: mustAddrs(t, tc.v4), v6: mustAddrs(t, tc.v6)}
			m.launchpadConnect = func(_ context.Context, network, address string, _ launchpadControl) (net.Conn, error) {
				dials.Add(1)
				dialed = append(dialed, network+" "+address)
				return nil, errors.New("dial admitted")
			}

			client, err := m.launchpadClient()
			require.NoError(t, err)
			resp, err := doGetWithin(t, client, tc.request, 2*time.Second)
			if resp != nil {
				_ = resp.Body.Close()
			}
			require.Error(t, err)
			assert.Equal(t, tc.wantDial, dials.Load())
			if tc.wantBlocked {
				assert.ErrorIs(t, err, surfguard.ErrBlocked)
				assert.NotContains(t, err.Error(), "dial admitted")
				return
			}
			assert.False(t, errors.Is(err, surfguard.ErrBlocked))
			assert.Contains(t, err.Error(), "dial admitted")
			if tc.wantAddr != "" {
				assert.Contains(t, dialed, tc.wantAddr)
			}
		})
	}
}

// TestBC5Lane_IgnoresBenchmarkingCarveOut: the connect seam and the lookup
// fixture belong to the Launchpad lane. A benchmarking literal on the BC5
// lane is still refused, and the Launchpad dialer is not asked.
func TestBC5Lane_IgnoresBenchmarkingCarveOut(t *testing.T) {
	clearProxyEnv(t)
	var dials atomic.Int32
	m := laneManager(t, "https://3.basecampapi.com")
	m.launchpadLookup = fixedLookup{v4: mustAddrs(t, []string{"198.18.0.1"})}
	m.launchpadConnect = func(context.Context, string, string, launchpadControl) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("dial admitted")
	}

	client, err := m.bc5Client()
	require.NoError(t, err)
	resp, err := doGetWithin(t, client, "https://198.18.0.1/token", 2*time.Second)
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err)
	assert.ErrorIs(t, err, surfguard.ErrBlocked)
	assert.Zero(t, dials.Load())
}

func doGetWithin(t *testing.T, client *http.Client, rawURL string, d time.Duration) (*http.Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	require.NoError(t, err)
	return client.Do(req)
}

// TestWarnf_SanitizesRenderedMessage: url.Parse admits UTF-8 C1 controls in
// a host, and EscapedPath only covers the path — so the sink scrubs the
// whole rendered warning, whichever field carried the control.
func TestWarnf_SanitizesRenderedMessage(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTP_PROXY", "http://proxy.corp.example:3128")

	var warnings []string
	m := laneManager(t, "https://3.basecampapi.com")
	m.Warnf = func(format string, args ...any) { warnings = append(warnings, fmt.Sprintf(format, args...)) }

	client, err := m.bc5Client()
	require.NoError(t, err)
	resp, reqErr := doGet(t, client, "http://evil\u009b31m.example/token%1b%5b31m")
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Error(t, reqErr)

	require.NotEmpty(t, warnings, "the ignored-proxy warning fires before the request is refused")
	for _, w := range warnings {
		assert.NotContains(t, w, "\u009b")
		assert.NotContains(t, w, "\x1b")
		assert.NotContains(t, w, "\n")
		assert.Contains(t, w, "evil31m.example", "C1 control stripped, host otherwise intact")
	}
}
