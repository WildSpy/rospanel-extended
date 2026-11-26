package mtproto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/netip"
	"net/url"
	"strings"
)

// WEB proxy (Telegram Desktop 7.1+, Android, iOS): the client opens no MTProto socket.
// A hidden WebView loads https://<host>/?bridge=<capability> from the server's own HTTPS site, and
// the page there carries the client's MTProxy streams over a same-origin WebSocket to
// this package (web.go), which hands each one on exactly as a fake-TLS connection is.
//
// The wire contract is Telegram's: tdesktop docs/web-proxy-plan.md and
// telegramdesktop/tproxy-server PROTOCOL.md ("WEB proxy protocol v1").

// webCapContext is the frozen v1 domain-separation label of the bridge capability; the
// host follows it after a newline.
const webCapContext = "tdesktop-web-proxy-bridge-v1\n"

// webCapLen is a capability's length: an unpadded base64url SHA-256.
const webCapLen = 43

// webSecret is the secret a WEB link carries, as bytes: "dd" (random padding, the
// transport WEB clients must use — tdesktop refuses "ee" for WEB) and the user's key.
func webSecret(uuid string) []byte {
	s := Secret(uuid)
	return append([]byte{0xdd}, s[:]...)
}

// webCapability derives the bridge capability for host from the secret's bytes, the
// leading dd byte included: base64url(HMAC-SHA256(secret, context ‖ host)).
func webCapability(secret []byte, host string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(webCapContext))
	m.Write([]byte(host))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// WebSecretHex is a user's WEB secret as a Telegram client takes it: "dd" and the key.
func WebSecretHex(uuid string) string {
	return hex.EncodeToString(webSecret(uuid))
}

// WebProxyLink is the tg://webproxy link that adds a WEB proxy to Telegram. The
// port is 443 and is not in the link: Telegram neither takes nor shows one.
func WebProxyLink(host, uuid string) string {
	return "tg://webproxy?" + webProxyQuery(host, uuid)
}

// WebProxyWebLink is WebProxyLink as an https://t.me address.
func WebProxyWebLink(host, uuid string) string {
	return "https://t.me/webproxy?" + webProxyQuery(host, uuid)
}

func webProxyQuery(host, uuid string) string {
	q := url.Values{}
	q.Set("server", host)
	q.Set("secret", WebSecretHex(uuid))
	return q.Encode()
}

// WebHost is host as a WEB proxy address — lowercase ASCII, a real DNS name of two
// labels or more — or "" when it cannot be one: Telegram refuses IP addresses (and the
// shorthands browsers read as one), single labels, ports, a trailing dot and non-ASCII
// names (an IDN goes in its xn-- form).
func WebHost(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" || len(h) > 253 || strings.HasSuffix(h, ".") {
		return ""
	}
	if _, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		return ""
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return ""
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return ""
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return ""
			}
		}
	}
	// WHATWG URL parsing reads a host whose last label is numeric (or 0x…) as an IPv4
	// address, so a browser would never ask for it by name.
	last := labels[len(labels)-1]
	if strings.HasPrefix(last, "0x") || strings.Trim(last, "0123456789") == "" {
		return ""
	}
	return h
}
