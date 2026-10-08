package auth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	surfguard "github.com/basecamp/surfguard/go"
	"golang.org/x/net/idna"
)

// benchmarkingPrefix is RFC 2544's 198.18.0.0/15. Some DNS-based transparent
// proxies publish an address in this range — almost always 198.18.0.1 — as
// the answer for the name they intercept. Packets to that address are the
// proxy, not a host on a private LAN. surfguard refuses the range twice:
// once in the default IPv4 deny table and again as IANA special-use.
// Allow re-admits the default table and does not re-admit special-use, so
// DefaultIssuerPolicy().Allow(benchmarkingPrefix) still blocks 198.18.0.1.
//
// relaxedBenchmarkPolicy is the same port stance as the issuer policy with
// the special-use tables off and this one prefix allowed. An address the
// relaxed policy admits, which the live policy refuses, is refused only
// because of the benchmarking range.
var (
	benchmarkingPrefix      = netip.MustParsePrefix("198.18.0.0/15")
	relaxedBenchmarkPolicy  = surfguard.Policy{}.AllowAllPorts().Allow(benchmarkingPrefix)
	errLaunchpadLookup      = errors.New("launchpad anchor lookup incomplete")
	publicRoutableSentinel  = netip.MustParseAddr("1.1.1.1")
	maxLaunchpadLookupAddrs = 256
)

// launchpadLookup is the DNS seam for the Launchpad anchor dialer.
// *net.Resolver satisfies it. A nil lookup uses net.DefaultResolver.
type launchpadLookup interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// launchpadControl is the dial gate. A non-nil error refuses the address;
// the caller must not open a socket after it.
type launchpadControl func(ctx context.Context, network, address string, c syscall.RawConn) error

// launchpadConnectFunc places a TCP connection that control has already
// admitted. Production uses net.Dialer, which runs control again on the
// real socket. Tests record the admission and return without dialing.
type launchpadConnectFunc func(ctx context.Context, network, address string, control launchpadControl) (net.Conn, error)

// launchpadGuardedTransport is the Launchpad lane's address-policed
// round tripper. An anchor that is not a DNS name — a literal
// BASECAMP_LAUNCHPAD_URL, or httptest's 127.0.0.1 — keeps surfguard's own
// dialer, loopback admission included. A named anchor keeps the same
// policy and additionally dials 198.18.0.0/15 when that name's answers
// are refused solely for being in the range. See dialLaunchpadAnchor.
func (m *Manager) launchpadGuardedTransport(policy surfguard.Policy, anchorURL string) http.RoundTripper {
	anchor, ok := launchpadAnchorName(anchorURL)
	if !ok {
		return policy.RoundTripper()
	}
	lookup := m.launchpadLookup
	connect := m.launchpadConnect
	transport := policy.Transport()
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialLaunchpadAnchor(ctx, policy, anchor, lookup, connect, network, address)
	}
	return launchpadShape{next: transport}
}

// launchpadShape refuses a malformed request URL before the transport can
// normalize the host. This is the check surfguard's unexported roundTripper
// performs: scheme http or https, a bracketed authority must be IPv6, and
// the host must be ASCII. The last rule matters because http.Transport
// IDNA-converts a non-ASCII host before dialing, so the dialer would
// otherwise judge a different name than the one in the request.
type launchpadShape struct {
	next http.RoundTripper
}

func (s launchpadShape) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := launchpadRequestShape(req); err != nil {
		return nil, err
	}
	return s.next.RoundTrip(req)
}

func launchpadRequestShape(req *http.Request) error {
	if req == nil || req.URL == nil {
		return &surfguard.Violation{Reason: surfguard.ReasonMalformedHost}
	}
	switch req.URL.Scheme {
	case "http", "https":
	default:
		return &surfguard.Violation{Reason: surfguard.ReasonScheme}
	}
	return launchpadHostShape(req.URL)
}

func launchpadHostShape(u *url.URL) error {
	host := u.Hostname()
	if host == "" {
		return &surfguard.Violation{Reason: surfguard.ReasonMalformedHost}
	}
	if len(u.Host) > 0 && u.Host[0] == '[' {
		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.Is6() || addr.Zone() != "" {
			return &surfguard.Violation{Host: u.Host, Reason: surfguard.ReasonMalformedHost}
		}
	}
	if len(host) > 255 {
		return &surfguard.Violation{Host: host, Reason: surfguard.ReasonMalformedHost}
	}
	for i := 0; i < len(host); i++ {
		if host[i] == 0 || host[i] >= 0x80 || host[i] == '%' {
			return &surfguard.Violation{Host: host, Reason: surfguard.ReasonMalformedHost}
		}
	}
	return nil
}

// dialLaunchpadAnchor dials one Launchpad-lane address. Anything that is
// not the anchor name — other hosts, IP literals, a lookup that did not
// finish — stays on the unmodified policy dialer. The anchor is dialed to
// the addresses this lookup returned, under a control that admits
// 198.18.0.0/15, only when every one of those addresses is refused solely
// for being in that range. A mixed answer, or any genuinely private
// address, is refused with no socket: a second lookup must not be allowed
// to hide an answer we have already seen.
func dialLaunchpadAnchor(ctx context.Context, policy surfguard.Policy, anchor string, lookup launchpadLookup, connect launchpadConnectFunc, network, address string) (net.Conn, error) {
	fallback := func() (net.Conn, error) {
		return policy.DialContext(ctx, network, address)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return fallback()
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return fallback()
	}
	name, ok := canonicalOAuthHost(host)
	if !ok || name != anchor {
		if !ok {
			return fallback()
		}
		// A different name can still be judged from this lookup so a test
		// (and a rebinding between two lookups) cannot turn a private
		// answer into a public dial. Names that resolve to a public
		// address fall through to the unmodified dialer.
		return dialOrRefuseResolved(ctx, policy, name, port, network, lookup, connect, false, fallback)
	}
	return dialOrRefuseResolved(ctx, policy, name, port, network, lookup, connect, true, fallback)
}

func dialOrRefuseResolved(ctx context.Context, policy surfguard.Policy, name, port, network string, lookup launchpadLookup, connect launchpadConnectFunc, anchor bool, fallback func() (net.Conn, error)) (net.Conn, error) {
	if lookup == nil {
		lookup = net.DefaultResolver
	}
	addrs, err := lookupLaunchpadHost(ctx, lookup, name)
	if err != nil {
		return fallback()
	}
	if anchor && portAllowed(port) && refusedOnlyAsBenchmarkingRange(policy, addrs) {
		if connect == nil {
			connect = defaultLaunchpadConnect
		}
		return dialBenchmarkingAddrs(ctx, network, port, addrs, policy, connect)
	}
	if everyAddrBlocked(policy, addrs) {
		return nil, &surfguard.Violation{
			Host:   name,
			Addr:   addrs[0].Unmap(),
			Reason: surfguard.ReasonBlockedAddr,
		}
	}
	return fallback()
}

func portAllowed(port string) bool {
	n, err := strconv.ParseUint(port, 10, 16)
	return err == nil && n > 0
}

// launchpadAnchorName is the anchor hostname in the form dial comparison
// uses: IDNA ASCII, case-folded, one trailing dot removed, brackets already
// stripped by url.Hostname. An IP literal is not a name — the carve-out
// refuses a URL that names 198.18.0.1 directly.
func launchpadAnchorName(anchorURL string) (string, bool) {
	u, err := url.Parse(anchorURL)
	if err != nil {
		return "", false
	}
	return canonicalOAuthHost(u.Hostname())
}

func canonicalOAuthHost(host string) (string, bool) {
	if host == "" {
		return "", false
	}
	host = strings.TrimSuffix(host, ".")
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil || ascii == "" {
		return "", false
	}
	if _, err := netip.ParseAddr(ascii); err == nil {
		return "", false
	}
	return ascii, true
}

// refusedOnlyAsBenchmarkingRange reports whether every address is inside
// 198.18.0.0/15 and the live policy refuses it only for that. A policy that
// also refuses ordinary public space is not widened. Mapped and non-IPv4
// answers fail the check: a hostile AAAA spelling of the placeholder stays
// on the unmodified policy, which unmaps at dial time and still refuses.
func refusedOnlyAsBenchmarkingRange(policy surfguard.Policy, addrs []netip.Addr) bool {
	if len(addrs) == 0 || policy.Blocked(publicRoutableSentinel) {
		return false
	}
	for _, addr := range addrs {
		if !plainBenchmarkingAddr(addr) || !policy.Blocked(addr) || relaxedBenchmarkPolicy.Blocked(addr) {
			return false
		}
	}
	return true
}

func plainBenchmarkingAddr(addr netip.Addr) bool {
	return addr.IsValid() && addr.Is4() && addr.Zone() == "" && benchmarkingPrefix.Contains(addr)
}

// everyAddrBlocked reports whether the unmodified policy would refuse every
// address at dial time. Judgment uses the unmapped address, matching
// surfguard's dial layer, where the kernel connects to the embedded IPv4.
func everyAddrBlocked(policy surfguard.Policy, addrs []netip.Addr) bool {
	if len(addrs) == 0 {
		return false
	}
	for _, addr := range addrs {
		if !addr.IsValid() || !policy.Blocked(addr.Unmap()) {
			return false
		}
	}
	return true
}

func lookupLaunchpadHost(ctx context.Context, lookup launchpadLookup, host string) ([]netip.Addr, error) {
	var v6 []netip.Addr
	var err6 error
	done := make(chan struct{})
	go func() {
		defer close(done)
		v6, err6 = lookup.LookupNetIP(ctx, "ip6", host)
	}()
	v4, err4 := lookup.LookupNetIP(ctx, "ip4", host)
	<-done
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !lookupDefinitive(err4) || !lookupDefinitive(err6) {
		return nil, errLaunchpadLookup
	}
	if len(v4)+len(v6) == 0 || len(v4)+len(v6) > maxLaunchpadLookupAddrs {
		return nil, errLaunchpadLookup
	}
	out := make([]netip.Addr, 0, len(v4)+len(v6))
	for _, addr := range v4 {
		if !addr.IsValid() || addr.Zone() != "" || !addr.Unmap().Is4() {
			return nil, errLaunchpadLookup
		}
		out = append(out, addr.Unmap())
	}
	for _, addr := range v6 {
		if !addr.IsValid() || addr.Zone() != "" || addr.Is4() {
			return nil, errLaunchpadLookup
		}
		out = append(out, addr)
	}
	if len(out) == 0 {
		return nil, errLaunchpadLookup
	}
	return out, nil
}

func lookupDefinitive(err error) bool {
	if err == nil {
		return true
	}
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// admitBenchmarkingRange admits a plain address in 198.18.0.0/15 that the
// rest of the policy would allow. Every other address, network, or parse
// failure is handed to the live policy, which still refuses it. The issuer
// policy allows every port; the carve-out does not grow a port restriction
// the lane does not have.
func admitBenchmarkingRange(policy surfguard.Policy) launchpadControl {
	return func(ctx context.Context, network, address string, c syscall.RawConn) error {
		if network != "tcp4" && network != "tcp6" {
			return policy.ControlContext(ctx, network, address, c)
		}
		ap, err := netip.ParseAddrPort(address)
		if err != nil || ap.Port() == 0 || ap.Addr().Is4In6() {
			return policy.ControlContext(ctx, network, address, c)
		}
		if !refusedOnlyAsBenchmarkingRange(policy, []netip.Addr{ap.Addr()}) {
			return policy.ControlContext(ctx, network, address, c)
		}
		return nil
	}
}

func dialBenchmarkingAddrs(ctx context.Context, network, port string, addrs []netip.Addr, policy surfguard.Policy, connect launchpadConnectFunc) (net.Conn, error) {
	control := admitBenchmarkingRange(policy)
	var first error
	for _, addr := range addrs {
		conn, err := dialAdmitted(ctx, network, net.JoinHostPort(addr.String(), port), control, connect)
		if err == nil {
			return conn, nil
		}
		if first == nil {
			first = err
		}
	}
	if first == nil {
		return nil, &surfguard.Violation{Reason: surfguard.ReasonBlockedAddr}
	}
	return nil, first
}

func dialAdmitted(ctx context.Context, network, address string, control launchpadControl, connect launchpadConnectFunc) (net.Conn, error) {
	fam, err := tcpFamily(network, address)
	if err != nil {
		return nil, err
	}
	if err := control(ctx, fam, address, nil); err != nil {
		return nil, err
	}
	return connect(ctx, fam, address, control)
}

func tcpFamily(network, address string) (string, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return "", &surfguard.Violation{Host: address, Reason: surfguard.ReasonMalformedHost}
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "", &surfguard.Violation{Host: host, Reason: surfguard.ReasonMalformedHost}
	}
	switch network {
	case "tcp4":
		if addr.Is4() {
			return "tcp4", nil
		}
	case "tcp6":
		if !addr.Is4() {
			return "tcp6", nil
		}
	case "tcp":
		if addr.Is4() {
			return "tcp4", nil
		}
		return "tcp6", nil
	}
	return "", &surfguard.Violation{Reason: surfguard.ReasonNetwork}
}

func defaultLaunchpadConnect(ctx context.Context, network, address string, control launchpadControl) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:        30 * time.Second,
		KeepAlive:      30 * time.Second,
		ControlContext: control,
	}
	return dialer.DialContext(ctx, network, address)
}
