package mtproto

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// The normative vectors of tdesktop docs/web-proxy-plan.md §10 (root base path).
func TestWebCapabilityVectors(t *testing.T) {
	t.Parallel()
	for _, v := range []struct{ secret, want string }{
		{"000102030405060708090a0b0c0d0e0f", "MHLEY5PmW1GWqJkSrlmJpvJUiLhBH_QKy6yKg8a0JPk"},
		{"dd000102030405060708090a0b0c0d0e0f", "IpJrt3e7sKtzPyoXy6w-Zj6GGEvsvclN66JzQEfPYLA"},
	} {
		key, _ := hex.DecodeString(v.secret)
		if got := webCapability(key, "proxy.example.com"); got != v.want {
			t.Errorf("secret %s: capability %s, want %s", v.secret, got, v.want)
		}
	}
}

func TestWebLinks(t *testing.T) {
	t.Parallel()
	s := Secret(uuidA)
	want := "dd" + hex.EncodeToString(s[:])
	if got := WebSecretHex(uuidA); got != want {
		t.Fatalf("secret %s, want %s", got, want)
	}
	if got := WebProxyLink("proxy.example.com", uuidA); got != "tg://webproxy?secret="+want+"&server=proxy.example.com" {
		t.Fatalf("link %s", got)
	}
	if got := WebProxyWebLink("proxy.example.com", uuidA); !strings.HasPrefix(got, "https://t.me/webproxy?") || strings.Contains(got, "port=") {
		t.Fatalf("web link %s", got)
	}
}

func TestWebHost(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"Proxy.Example.COM":  "proxy.example.com",
		" vpn.example.ru ":   "vpn.example.ru",
		"xn--80ak6aa92e.com": "xn--80ak6aa92e.com",
		"203.0.113.5":        "",
		"[2001:db8::1]":      "",
		"localhost":          "",
		"example.com.":       "",
		"example.com:443":    "",
		"пример.рф":          "",
		"a.0x7f":             "",
		"host.123":           "",
		"-bad.example.com":   "",
		"":                   "",
	} {
		if got := WebHost(in); got != want {
			t.Errorf("WebHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseWebFrames(t *testing.T) {
	t.Parallel()
	b := appendWebFrame(nil, wfOpen, 7, nil)
	b = appendWebFrame(b, wfData, 7, []byte("abc"))
	f, err := parseWebFrames(b)
	if err != nil || len(f) != 2 || f[1].typ != wfData || f[1].stream != 7 || string(f[1].payload) != "abc" {
		t.Fatalf("parsed %+v, %v", f, err)
	}
	for name, bad := range map[string][]byte{
		"empty":   nil,
		"partial": b[:len(b)-1],
		"header":  b[:5],
		"unknown": appendWebFrame(nil, 0x07, 1, nil),
		"too big": {wfData, 0, 0, 1, 0, 0x10, 0, 1},
	} {
		if _, err := parseWebFrames(bad); err == nil {
			t.Errorf("%s batch accepted", name)
		}
	}
}

const webTestHost = "proxy.example.com"

// startWeb runs the lane with WEB on, in front of a stand-in site that answers "decoy".
func startWeb(t *testing.T) (*Server, *httptest.Server, *fakeXray) {
	t.Helper()
	x := newFakeXray(t)
	s := New(x.ln.Addr().String())
	if err := s.Apply(Listen{Web: webTestHost}, "", []User{{Email: "u1", UUID: uuidA}, {Email: "u2", UUID: uuidB}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	site := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "decoy")
	})
	srv := httptest.NewServer(s.WebHandler(site))
	t.Cleanup(srv.Close)
	return s, srv, x
}

func getPage(t *testing.T, srv *httptest.Server, host, query string) (int, string, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/?"+query, nil)
	req.Host = host
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), resp.Header
}

var tokenRe = regexp.MustCompile(`TOKEN="([A-Za-z0-9_-]{43})"`)

// bridgeToken loads uuid's bridge page and returns the carrier token in it.
func bridgeToken(t *testing.T, srv *httptest.Server, uuid string) string {
	t.Helper()
	capability := webCapability(webSecret(uuid), webTestHost)
	code, body, h := getPage(t, srv, webTestHost, "bridge="+capability)
	if code != http.StatusOK || !strings.Contains(h.Get("Content-Security-Policy"), "connect-src 'self' wss://"+webTestHost) {
		t.Fatalf("bridge page: %d %q", code, body)
	}
	m := tokenRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no token in the page")
	}
	if strings.Contains(body, capability) || strings.Contains(body, WebSecretHex(uuid)) {
		t.Fatalf("the page carries the capability or the secret")
	}
	return m[1]
}

func TestWebPageNeedsTheCapability(t *testing.T) {
	t.Parallel()
	_, srv, _ := startWeb(t)
	good := webCapability(webSecret(uuidA), webTestHost)
	plain := Secret(uuidA)
	for name, c := range map[string]struct{ host, query string }{
		"no query":       {webTestHost, ""},
		"random":         {webTestHost, "bridge=" + strings.Repeat("A", 43)},
		"no dd byte":     {webTestHost, "bridge=" + webCapability(plain[:], webTestHost)},
		"another host":   {"other.example.com", "bridge=" + good},
		"extra param":    {webTestHost, "bridge=" + good + "&x=1"},
		"another's host": {webTestHost, "bridge=" + webCapability(webSecret(uuidA), "other.example.com")},
	} {
		if code, body, _ := getPage(t, srv, c.host, c.query); code != http.StatusNotFound || body != "decoy" {
			t.Errorf("%s: %d %q, want the site", name, code, body)
		}
	}
	if code, _, _ := getPage(t, srv, strings.ToUpper(webTestHost)+":443", "bridge="+good); code != http.StatusOK {
		t.Fatalf("Host with case and port: %d", code)
	}
}

// wsClient is the bridge page's end of a carrier.
type wsClient struct {
	c  net.Conn
	br *bufio.Reader
}

func dialCarrier(t *testing.T, srv *httptest.Server, protocol string) (*wsClient, int) {
	t.Helper()
	c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	var key [16]byte
	_, _ = rand.Read(key[:])
	fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Protocol: %s\r\n"+
		"Origin: https://%s\r\n\r\n", webWSPath, webTestHost, base64.StdEncoding.EncodeToString(key[:]), protocol, webTestHost)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A 101 has no body (NoBody) and the WebSocket stream stays in br; anything else
	// is the site's answer, read to its end here.
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusSwitchingProtocols && resp.Header.Get("Sec-WebSocket-Protocol") != protocol {
		t.Fatalf("subprotocol %q echoed for %q", resp.Header.Get("Sec-WebSocket-Protocol"), protocol)
	}
	return &wsClient{c: c, br: br}, resp.StatusCode
}

func (w *wsClient) send(t *testing.T, payload []byte) {
	t.Helper()
	h := []byte{0x82}
	switch n := len(payload); {
	case n < 126:
		h = append(h, 0x80|byte(n))
	case n <= 0xffff:
		h = append(h, 0x80|126, byte(n>>8), byte(n))
	default:
		h = append(h, 0x80|127)
		h = binary.BigEndian.AppendUint64(h, uint64(n))
	}
	mask := [4]byte{1, 2, 3, 4}
	h = append(h, mask[:]...)
	body := bytes.Clone(payload)
	for i := range body {
		body[i] ^= mask[i&3]
	}
	if _, err := w.c.Write(append(h, body...)); err != nil {
		t.Fatal(err)
	}
}

// recv reads the next binary message's frames, skipping PING.
func (w *wsClient) recv(t *testing.T) []webFrame {
	t.Helper()
	for {
		var h [2]byte
		if _, err := io.ReadFull(w.br, h[:]); err != nil {
			t.Fatalf("read: %v", err)
		}
		n := uint64(h[1] & 0x7f)
		switch n {
		case 126:
			var b [2]byte
			_, _ = io.ReadFull(w.br, b[:])
			n = uint64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			_, _ = io.ReadFull(w.br, b[:])
			n = binary.BigEndian.Uint64(b[:])
		}
		p := make([]byte, n)
		if _, err := io.ReadFull(w.br, p); err != nil {
			t.Fatalf("read: %v", err)
		}
		if op := h[0] & 0x0f; op != wsOpBinary {
			t.Fatalf("opcode %x", op)
		}
		f, err := parseWebFrames(p)
		if err != nil {
			t.Fatalf("relay sent a bad batch: %v", err)
		}
		var out []webFrame
		for _, x := range f {
			if x.typ != wfPing {
				out = append(out, x)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
}

func (w *wsClient) hello(t *testing.T) {
	t.Helper()
	w.send(t, appendWebFrame(nil, wfHello, 0, []byte{1}))
	f := w.recv(t)
	if len(f) != 1 || f[0].typ != wfWelcome || f[0].stream != 0 || len(f[0].payload) != 0 {
		t.Fatalf("first relay message %+v, want one WELCOME", f)
	}
}

func TestWebCarrierReachesTheDataCentre(t *testing.T) {
	t.Parallel()
	s, srv, x := startWeb(t)
	w, code := dialCarrier(t, srv, "tproxy-v1."+bridgeToken(t, srv, uuidB))
	if code != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %d", code)
	}
	w.hello(t)
	if s.WebCarriers() != 1 {
		t.Fatalf("carriers %d", s.WebCarriers())
	}

	// The client's MTProxy connection, as Telegram Desktop makes it for a dd secret: the
	// obfuscated opening under the user's key, then the stream — no fake TLS.
	secret := Secret(uuidB)
	opening, send, recv := openFrame(-4, secret[:])
	msg := []byte("hello telegram")
	enc := bytes.Clone(msg)
	send.XORKeyStream(enc, enc)
	batch := appendWebFrame(nil, wfOpen, 1, nil)
	batch = appendWebFrame(batch, wfData, 1, append(bytes.Clone(opening), enc...))
	w.send(t, batch)

	var back []byte
	for len(back) < len(msg) {
		for _, f := range w.recv(t) {
			switch {
			case f.typ == wfData && f.stream == 1:
				back = append(back, f.payload...)
			case f.typ == wfWindow && f.stream == 1:
			default:
				t.Fatalf("unexpected frame %+v", f)
			}
		}
	}
	recv.XORKeyStream(back, back)
	if string(back) != "HELLO TELEGRAM" {
		t.Fatalf("echo %q", back)
	}
	x.mu.Lock()
	targets, users, srcs := x.targets, x.users, x.srcs
	x.mu.Unlock()
	if len(targets) != 1 || targets[0] != "149.154.167.91:443" || users[0] != strings.ReplaceAll(uuidB, "-", "") || srcs[0] != "TCP4" {
		t.Fatalf("Xray saw %v as %v from %v", targets, users, srcs)
	}

	// The client closes the stream: the relay lets Telegram go and stays up.
	w.send(t, appendWebFrame(nil, wfClose, 1, nil))
	deadline := time.Now().Add(5 * time.Second)
	for s.Open() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.Open() != 0 {
		t.Fatalf("session still open after CLOSE")
	}
	// Late DATA for the closed stream is an ordinary race, not an error.
	w.send(t, appendWebFrame(nil, wfData, 1, []byte("late")))
	w.send(t, appendWebFrame(nil, wfOpen, 2, nil))
	w.send(t, appendWebFrame(nil, wfData, 2, bytes.Repeat([]byte("not an opening "), 5)))
	for {
		f := w.recv(t)
		if f[0].typ == wfBye {
			t.Fatalf("BYE after an ordinary close race")
		}
		if f[0].typ == wfClose && f[0].stream == 2 {
			break // a stream that does not open with the user's key is closed, alone
		}
	}
}

// More than a window each way: the relay must hand credit back as Telegram takes the
// client's bytes, and send no more than the client gives it.
func TestWebCarrierFlowControl(t *testing.T) {
	t.Parallel()
	_, srv, _ := startWeb(t)
	w, _ := dialCarrier(t, srv, "tproxy-v1."+bridgeToken(t, srv, uuidA))
	_ = w.c.SetDeadline(time.Now().Add(60 * time.Second))
	w.hello(t)
	secret := Secret(uuidA)
	opening, send, recv := openFrame(2, secret[:])
	w.send(t, appendWebFrame(appendWebFrame(nil, wfOpen, 5, nil), wfData, 5, opening))

	const total = 6 << 20
	up := bytes.Repeat([]byte("abcdefgh"), total/8)
	want := bytes.ToUpper(up)
	enc := bytes.Clone(up)
	send.XORKeyStream(enc, enc)

	sendCredit := wfWindow0 - len(opening)
	recvCredit := wfWindow0
	var got []byte
	sent := 0
	for len(got) < total {
		// Send what credit allows, 64 KiB at a time.
		for sent < total && sendCredit > 0 {
			n := min(wfDataChunk, total-sent, sendCredit)
			w.send(t, appendWebFrame(nil, wfData, 5, enc[sent:sent+n]))
			sent += n
			sendCredit -= n
		}
		for _, f := range w.recv(t) {
			switch f.typ {
			case wfWindow:
				d, _ := windowDelta(f.payload)
				sendCredit += int(d)
			case wfData:
				if len(f.payload) > recvCredit {
					t.Fatalf("relay sent %d past the %d credit left", len(f.payload), recvCredit)
				}
				recvCredit -= len(f.payload)
				got = append(got, f.payload...)
				// Drained at once: grant it back.
				w.send(t, appendWebFrame(nil, wfWindow, 5, beUint32(uint32(len(f.payload)))))
				recvCredit += len(f.payload)
			default:
				t.Fatalf("unexpected frame %+v", f)
			}
		}
	}
	recv.XORKeyStream(got, got)
	if !bytes.Equal(got, want) {
		t.Fatal("the stream came back changed")
	}
}

func TestWebTokenIsOneUse(t *testing.T) {
	t.Parallel()
	_, srv, _ := startWeb(t)
	tok := bridgeToken(t, srv, uuidA)
	if _, code := dialCarrier(t, srv, "tproxy-v1."+tok); code != http.StatusSwitchingProtocols {
		t.Fatalf("first upgrade: %d", code)
	}
	if _, code := dialCarrier(t, srv, "tproxy-v1."+tok); code != http.StatusNotFound {
		t.Fatalf("second upgrade with the same token: %d, want the site", code)
	}
	if _, code := dialCarrier(t, srv, "tproxy-v1."+strings.Repeat("A", 43)); code != http.StatusNotFound {
		t.Fatalf("made-up token: %d, want the site", code)
	}
	tok = bridgeToken(t, srv, uuidA)
	if _, code := dialCarrier(t, srv, "tproxy-v1."+tok+", chat"); code != http.StatusNotFound {
		t.Fatalf("two subprotocols: %d, want the site", code)
	}
}

func TestWebProtocolErrorSaysBye(t *testing.T) {
	t.Parallel()
	_, srv, _ := startWeb(t)
	for name, batch := range map[string][]byte{
		"data on an unknown stream": appendWebFrame(nil, wfData, 9, []byte("x")),
		"open twice":                appendWebFrame(appendWebFrame(nil, wfOpen, 3, nil), wfOpen, 3, nil),
		"window of zero":            appendWebFrame(appendWebFrame(nil, wfOpen, 3, nil), wfWindow, 3, []byte{0, 0, 0, 0}),
		"auth challenge":            appendWebFrame(nil, wfAuthChal, 0, nil),
		"hello again":               appendWebFrame(nil, wfHello, 0, []byte{1}),
	} {
		w, code := dialCarrier(t, srv, "tproxy-v1."+bridgeToken(t, srv, uuidA))
		if code != http.StatusSwitchingProtocols {
			t.Fatalf("%s: upgrade %d", name, code)
		}
		w.hello(t)
		w.send(t, batch)
		for {
			f := w.recv(t)
			if f[len(f)-1].typ == wfBye {
				break
			}
		}
	}
}

// The client may send a stream no more than the credit it was given: 4 MiB up front.
func TestWebDataPastTheWindow(t *testing.T) {
	t.Parallel()
	c := &carrier{user: &cred{}, streams: map[uint32]*webStream{}, closed: map[uint32]struct{}{}, wake: make(chan struct{}, 1)}
	c.cond = sync.NewCond(&c.mu)
	full := make([]byte, wfMaxPayload)
	frames := []webFrame{{typ: wfOpen, stream: 3}}
	for range wfWindow0 / wfMaxPayload {
		frames = append(frames, webFrame{typ: wfData, stream: 3, payload: full})
	}
	if err := c.handle(frames); err != nil {
		t.Fatalf("the whole window refused: %v", err)
	}
	if err := c.handle([]webFrame{{typ: wfData, stream: 3, payload: []byte{1}}}); err == nil {
		t.Fatal("a byte past the window accepted")
	}
	c.end()
}

func TestWebHelloMustComeFirst(t *testing.T) {
	t.Parallel()
	_, srv, _ := startWeb(t)
	w, _ := dialCarrier(t, srv, "tproxy-v1."+bridgeToken(t, srv, uuidA))
	w.send(t, appendWebFrame(nil, wfOpen, 1, nil))
	if f := w.recv(t); len(f) != 1 || f[0].typ != wfBye {
		t.Fatalf("OPEN before HELLO answered %+v", f)
	}
}

func TestApplyEndsARemovedUsersCarrier(t *testing.T) {
	t.Parallel()
	s, srv, _ := startWeb(t)
	w, _ := dialCarrier(t, srv, "tproxy-v1."+bridgeToken(t, srv, uuidA))
	w.hello(t)
	if err := s.Apply(Listen{Web: webTestHost}, "", []User{{Email: "u2", UUID: uuidB}}); err != nil {
		t.Fatal(err)
	}
	_ = w.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var ne net.Error
	if _, err := io.ReadAll(w.br); errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("carrier not ended: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for s.WebCarriers() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.WebCarriers() != 0 {
		t.Fatal("carrier still tracked")
	}
	// And with the lane off, the bridge is the site again.
	if err := s.Apply(Listen{}, "", []User{{Email: "u2", UUID: uuidB}}); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := getPage(t, srv, webTestHost, "bridge="+webCapability(webSecret(uuidB), webTestHost)); code != http.StatusNotFound {
		t.Fatalf("bridge with WEB off: %d", code)
	}
}
