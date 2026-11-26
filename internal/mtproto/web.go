package mtproto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Shu1t3/rospanel-shu1t3/internal/decoy"
)

// The WEB carrier relay (see webcap.go). The bridge page and its WebSocket are served on
// the server's own HTTPS site — the decoy behind Xray's TLS on :443 — for the one host
// the WEB links name; every other request goes on to the site untouched, and so does any
// request here without an authentic capability or token, so a stranger sees the decoy.
//
// One carrier is one WebSocket of one user's Telegram app; it multiplexes the
// client's MTProxy connections as streams. Each stream is the client's obfuscated
// connection exactly as it would have opened it to the lane's port, minus fake TLS, and
// goes to Telegram the same way: through Xray's mtproto-in under the user's UUID, so
// traffic, device limits and speed caps count it as for any lane.

const (
	// webTokenTTL is how long a bridge page's carrier token stays good, unused.
	webTokenTTL = 2 * time.Minute
	// webMaxTokens bounds the tokens outstanding: one per bridge page load.
	webMaxTokens = 4096
	// webMaxCarriers bounds the carriers open at once, webMaxUserCarriers one user's.
	// A Telegram app keeps one per process.
	webMaxCarriers     = 1024
	webMaxUserCarriers = 16
	// webMaxStreams bounds one carrier's streams; an OPEN over it is answered CLOSE,
	// which the client takes as one failed connection and retries.
	webMaxStreams = 256
	// webPingEvery is how often an idle carrier is pinged; one silent for webSilence —
	// no message, not even the PONG — is dropped.
	webPingEvery = 20 * time.Second
	webSilence   = 90 * time.Second
	// webWriteTimeout fails a carrier whose client stopped reading.
	webWriteTimeout = 30 * time.Second
	// webQueueLimit is how far behind a carrier's writer may fall before streams stop
	// handing it DATA; control frames are never held back.
	webQueueLimit = 8 << 20
	// webMaxQueued caps the frames queued on one carrier, control frames included.
	webMaxQueued = 1 << 16
	// webBatchBytes is the most one carrier message carries.
	webBatchBytes = 2 << 20
	// webGrantAt is how much returned credit a stream gathers before it sends WINDOW.
	webGrantAt = 256 << 10
	// webClosedKeep is how many closed stream ids a carrier remembers, so late frames
	// of an ordinary close race are dropped rather than taken for a protocol error.
	webClosedKeep = 4096
	// webMaxBuffered caps the client's DATA one carrier holds before Telegram took it,
	// all streams together (each is held to its 4 MiB window as well).
	webMaxBuffered = 64 << 20
)

// webState is what the WEB lane answers for: the host and each user's capability there.
type webState struct {
	host string
	caps map[string]*cred
}

func (w *webState) lookup(capability string) *cred {
	if len(capability) != webCapLen {
		return nil
	}
	c := w.caps[capability]
	if c == nil {
		return nil
	}
	// The map found it; the comparison is what a token check here is made of.
	if subtle.ConstantTimeCompare([]byte(c.webCap), []byte(capability)) != 1 {
		return nil
	}
	return c
}

func newWebState(host string, t *table) *webState {
	if host == "" {
		return nil
	}
	w := &webState{host: host, caps: make(map[string]*cred, len(t.list))}
	for _, c := range t.list {
		c.webCap = webCapability(webSecret(c.UUID), host)
		w.caps[c.webCap] = c
	}
	return w
}

// webTokens are the carrier tokens bridge pages were given: 32 random bytes, one use.
type webTokens struct {
	mu sync.Mutex
	m  map[string]webToken
}

type webToken struct {
	user    User
	expires time.Time
}

func (t *webTokens) issue(u User) string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	tok := base64.RawURLEncoding.EncodeToString(b[:])
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = map[string]webToken{}
	}
	if len(t.m) >= webMaxTokens {
		for k, v := range t.m {
			if now.After(v.expires) {
				delete(t.m, k)
			}
		}
		for k := range t.m { // still full: drop any, as a full cache would
			if len(t.m) < webMaxTokens {
				break
			}
			delete(t.m, k)
		}
	}
	t.m[tok] = webToken{user: u, expires: now.Add(webTokenTTL)}
	return tok
}

// take spends a token, if it is one and still good.
func (t *webTokens) take(tok string) (User, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.m[tok]
	if !ok {
		return User{}, false
	}
	delete(t.m, tok)
	return v.user, time.Now().Before(v.expires)
}

// WebHost is the host the WEB lane answers for, "" while it is off.
func (s *Server) WebHost() string {
	if w := s.web.Load(); w != nil {
		return w.host
	}
	return ""
}

// WebCarriers is how many WEB carriers are open.
func (s *Server) WebCarriers() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.carriers)
}

// WebHandler serves the WEB lane's bridge page and carrier in front of next — the
// server's own site — and hands it everything else, including any request here that
// does not authenticate.
func (s *Server) WebHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if st := s.web.Load(); st != nil && sameHost(r.Host, st.host) && s.serveWeb(w, r, st) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sameHost reports whether a request's Host names host.
func sameHost(reqHost, host string) bool {
	h := reqHost
	if hh, _, err := net.SplitHostPort(reqHost); err == nil {
		h = hh
	}
	return strings.EqualFold(h, host)
}

// serveWeb answers r when it is the lane's, and reports whether it was.
func (s *Server) serveWeb(w http.ResponseWriter, r *http.Request, st *webState) bool {
	switch r.URL.Path {
	case "/":
		// Exactly "GET /?bridge=<capability>" selects the bridge (tproxy-server's rule).
		q, ok := strings.CutPrefix(r.URL.RawQuery, "bridge=")
		if !ok || r.Method != http.MethodGet {
			return false
		}
		u := st.lookup(q)
		if u == nil {
			return false
		}
		w.Header().Set("Server", decoy.ServerName)
		serveWebPage(w, st.host, s.tokens.issue(u.User))
		return true
	case webWSPath:
		if !isWebSocketUpgrade(r) {
			return false
		}
		tok, ok := carrierToken(r)
		if !ok {
			return false
		}
		u, ok := s.tokens.take(tok)
		if !ok {
			return false
		}
		c := s.users.Load().byEmail[u.Email]
		if c == nil || c.UUID != u.UUID {
			return false
		}
		s.runCarrier(w, r, c, st, tok)
		return true
	}
	return false
}

// carrierToken is the token a carrier upgrade presents: its one subprotocol,
// "tproxy-v1.<token>".
func carrierToken(r *http.Request) (string, bool) {
	var protos []string
	for _, v := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				protos = append(protos, p)
			}
		}
	}
	if len(protos) != 1 {
		return "", false
	}
	tok, ok := strings.CutPrefix(protos[0], "tproxy-v1.")
	if !ok || len(tok) != webCapLen {
		return "", false
	}
	return tok, true
}

// carrier is one client's WEB carrier.
type carrier struct {
	s      *Server
	user   *cred
	host   string
	ws     *wsConn
	remote net.Addr

	mu      sync.Mutex
	cond    *sync.Cond // a stream's data, credit or queue room; the carrier ending
	dead    bool
	streams map[uint32]*webStream
	closed  map[uint32]struct{} // recently closed ids, oldest first in closedQ
	closedQ []uint32
	queue   [][]byte // frames waiting for the writer
	queued  int      // their bytes
	inTotal int      // the client's DATA held, every stream's
	wake    chan struct{}
}

// runCarrier takes the connection over and runs it until it ends.
func (s *Server) runCarrier(w http.ResponseWriter, r *http.Request, u *cred, st *webState, tok string) {
	c := &carrier{s: s, user: u, host: st.host, remote: webAddr(r.RemoteAddr),
		streams: map[uint32]*webStream{}, closed: map[uint32]struct{}{}, wake: make(chan struct{}, 1)}
	c.cond = sync.NewCond(&c.mu)
	if !s.trackCarrier(c) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	defer s.untrackCarrier(c)
	ws, err := wsAccept(w, r, "tproxy-v1."+tok) // the exact subprotocol, echoed
	if err != nil {
		return
	}
	c.mu.Lock()
	c.ws = ws
	dead := c.dead // Apply may have ended it while the upgrade was going on
	c.mu.Unlock()
	if dead {
		ws.close(1000)
		return
	}
	c.run()
}

func (s *Server) trackCarrier(c *carrier) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.carriers) >= webMaxCarriers || s.perUserWeb[c.user.Email] >= webMaxUserCarriers {
		return false
	}
	s.carriers[c] = struct{}{}
	s.perUserWeb[c.user.Email]++
	return true
}

func (s *Server) untrackCarrier(c *carrier) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.carriers[c]; !ok {
		return
	}
	delete(s.carriers, c)
	if s.perUserWeb[c.user.Email]--; s.perUserWeb[c.user.Email] <= 0 {
		delete(s.perUserWeb, c.user.Email)
	}
}

// webAddr is a client's address as the HTTP server saw it (behind the PROXY header,
// the client's own).
type webAddr string

func (webAddr) Network() string  { return "tcp" }
func (a webAddr) String() string { return string(a) }

var errWebProtocol = errors.New("mtproto: WEB protocol violation")

// run reads the client's messages until the carrier ends; the writer runs beside it.
func (c *carrier) run() {
	defer c.end()
	// The client says HELLO alone, and nothing before it; WELCOME goes back alone, the
	// relay's first frame — the client takes its first message only if it is exactly that.
	msg, err := c.read()
	if err != nil {
		return
	}
	f, err := parseWebFrames(msg)
	if err != nil || len(f) != 1 || f[0].typ != wfHello || f[0].stream != 0 ||
		len(f[0].payload) != 1 || f[0].payload[0] != 1 {
		c.bye()
		return
	}
	if err := c.ws.writeBinary(appendWebFrame(nil, wfWelcome, 0, nil)); err != nil {
		return
	}
	go c.writer()
	for {
		msg, err := c.read()
		if err != nil {
			return
		}
		frames, err := parseWebFrames(msg)
		if err == nil {
			err = c.handle(frames)
		}
		if err != nil {
			c.bye()
			return
		}
	}
}

func (c *carrier) read() ([]byte, error) {
	_ = c.ws.c.SetReadDeadline(time.Now().Add(webSilence))
	return c.ws.readMessage()
}

// bye tells the client its streams are gone, and the carrier with them.
func (c *carrier) bye() {
	c.mu.Lock()
	c.queue, c.queued = nil, 0 // nothing queued matters any more
	c.mu.Unlock()
	_ = c.ws.writeBinary(appendWebFrame(nil, wfBye, 0, nil))
}

// handle applies one message's frames.
func (c *carrier) handle(frames []webFrame) error {
	var open []*webStream
	defer func() {
		for _, st := range open {
			go st.run()
		}
	}()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, f := range frames {
		if f.stream == 0 {
			if f.typ != wfPong || len(f.payload) > wfMaxPing {
				return errWebProtocol
			}
			continue // any message is a sign of life: the read deadline was moved
		}
		st := c.streams[f.stream]
		_, wasClosed := c.closed[f.stream]
		switch f.typ {
		case wfOpen:
			if len(f.payload) != 0 || st != nil || wasClosed {
				return errWebProtocol
			}
			if len(c.streams) >= webMaxStreams {
				c.rememberLocked(f.stream)
				c.enqueueLocked(wfClose, f.stream, nil)
				continue
			}
			st = &webStream{c: c, id: f.stream, recvWin: wfWindow0, sendWin: wfWindow0}
			c.streams[f.stream] = st
			open = append(open, st)
		case wfData:
			if len(f.payload) == 0 {
				return errWebProtocol
			}
			if st == nil {
				if wasClosed {
					continue
				}
				return errWebProtocol
			}
			if uint32(len(f.payload)) > st.recvWin || c.inTotal+len(f.payload) > webMaxBuffered {
				return errWebProtocol
			}
			st.recvWin -= uint32(len(f.payload))
			st.in = append(st.in, f.payload)
			st.inLen += len(f.payload)
			c.inTotal += len(f.payload)
			c.cond.Broadcast()
		case wfWindow:
			d, ok := windowDelta(f.payload)
			if !ok {
				return errWebProtocol
			}
			if st == nil {
				if wasClosed {
					continue
				}
				return errWebProtocol
			}
			st.sendWin = uint32(min(uint64(st.sendWin)+uint64(d), math.MaxUint32))
			c.cond.Broadcast()
		case wfClose:
			if len(f.payload) != 0 {
				return errWebProtocol
			}
			if st == nil {
				if wasClosed {
					continue
				}
				return errWebProtocol
			}
			st.remoteClosed = true
			c.abortLocked(st)
		default:
			return errWebProtocol
		}
	}
	return nil
}

// rememberLocked notes id as closed; ids are never reused on a carrier.
func (c *carrier) rememberLocked(id uint32) {
	if _, ok := c.closed[id]; ok {
		return
	}
	if len(c.closedQ) >= webClosedKeep {
		delete(c.closed, c.closedQ[0])
		c.closedQ = c.closedQ[1:]
	}
	c.closed[id] = struct{}{}
	c.closedQ = append(c.closedQ, id)
}

// abortLocked ends a stream: it is forgotten, its reader and writer let go, and the
// client told unless it was the one to close it.
func (c *carrier) abortLocked(st *webStream) {
	if st.closed {
		return
	}
	st.closed = true
	c.inTotal -= st.inLen
	st.in, st.inLen = nil, 0
	delete(c.streams, st.id)
	c.rememberLocked(st.id)
	if !st.remoteClosed && !c.dead {
		c.enqueueLocked(wfClose, st.id, nil)
	}
	c.cond.Broadcast()
}

// enqueueLocked queues a frame for the writer. A carrier that queued more frames than
// it could ever send is failed.
func (c *carrier) enqueueLocked(t byte, id uint32, payload []byte) {
	if c.dead {
		return
	}
	if len(c.queue) >= webMaxQueued {
		c.dead = true
		c.cond.Broadcast()
		if c.ws != nil {
			go c.ws.close(1011)
		}
		return
	}
	f := appendWebFrame(make([]byte, 0, wfHeaderLen+len(payload)), t, id, payload)
	c.queue = append(c.queue, f)
	c.queued += len(f)
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// writer sends what is queued, a batch per message, and pings an idle carrier.
func (c *carrier) writer() {
	ping := time.NewTicker(webPingEvery)
	defer ping.Stop()
	for {
		select {
		case <-c.wake:
		case <-ping.C:
			var p [8]byte
			_, _ = rand.Read(p[:])
			c.mu.Lock()
			c.enqueueLocked(wfPing, 0, p[:])
			c.mu.Unlock()
			continue
		}
		for {
			c.mu.Lock()
			if c.dead {
				c.mu.Unlock()
				return
			}
			n, size := 0, 0
			for n < len(c.queue) && n < wfMaxBatch && (n == 0 || size+len(c.queue[n]) <= webBatchBytes) {
				size += len(c.queue[n])
				n++
			}
			if n == 0 {
				c.mu.Unlock()
				break
			}
			batch := make([]byte, 0, size)
			for _, f := range c.queue[:n] {
				batch = append(batch, f...)
			}
			c.queue = c.queue[n:]
			if len(c.queue) == 0 {
				c.queue = nil
			}
			c.queued -= size
			c.cond.Broadcast() // room for the streams' DATA
			c.mu.Unlock()
			if err := c.ws.writeBinary(batch); err != nil {
				c.ws.close(1011)
				return
			}
		}
	}
}

// end closes the carrier and every stream on it.
func (c *carrier) end() {
	c.mu.Lock()
	c.dead = true
	for _, st := range c.streams {
		st.closed = true
		st.in, st.inLen = nil, 0
	}
	c.streams = map[uint32]*webStream{}
	c.inTotal = 0
	c.queue, c.queued = nil, 0
	c.cond.Broadcast()
	c.mu.Unlock()
	select {
	case c.wake <- struct{}{}: // the writer sees the carrier dead and returns
	default:
	}
	if c.ws != nil {
		c.ws.close(1000)
	}
}

// kill ends the carrier from outside (Apply, Close): its reader fails and ends it.
func (c *carrier) kill() {
	c.mu.Lock()
	c.dead = true
	ws := c.ws
	c.cond.Broadcast()
	c.mu.Unlock()
	if ws != nil {
		ws.close(1000)
	}
}

// webStream is one MTProxy connection of the client, carried on a carrier. It is the
// client end serve and readClientFrame read from and write to.
type webStream struct {
	c  *carrier
	id uint32

	// Guarded by c.mu.
	in           [][]byte // the client's DATA, not read yet
	inLen        int
	recvWin      uint32 // what the client may still send
	grant        uint32 // read since the last WINDOW sent back
	sendWin      uint32 // what the client lets us send
	closed       bool
	remoteClosed bool
}

// run opens the stream as a fake-TLS connection is opened after its handshake: the
// client's obfuscated opening frame under the user's secret, then serve.
func (st *webStream) run() {
	t := time.AfterFunc(handshakeTimeout, func() { _ = st.Close() })
	dc, recv, send, err := readClientFrame(st, st.c.user.secret[:])
	if !t.Stop() || err != nil {
		_ = st.Close()
		return
	}
	st.c.s.serve(st, st, st.c.user, dc, recv, send)
	_ = st.Close()
}

// Read is the client's next bytes. The credit they used goes back once read — once they
// are on their way to Telegram — so a stalled Telegram stops the client, not our memory.
func (st *webStream) Read(p []byte) (int, error) {
	c := st.c
	c.mu.Lock()
	defer c.mu.Unlock()
	for st.inLen == 0 && !st.closed && !c.dead {
		c.cond.Wait()
	}
	if st.inLen == 0 {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) && len(st.in) > 0 {
		k := copy(p[n:], st.in[0])
		n += k
		if k == len(st.in[0]) {
			st.in[0] = nil
			st.in = st.in[1:]
		} else {
			st.in[0] = st.in[0][k:]
		}
	}
	st.inLen -= n
	c.inTotal -= n
	st.grant += uint32(n)
	// Coalesced as tdesktop does its own; never so far that the client runs short.
	if st.grant >= webGrantAt || st.recvWin < wfWindow0/2 {
		st.recvWin += st.grant
		c.enqueueLocked(wfWindow, st.id, beUint32(st.grant))
		st.grant = 0
	}
	return n, nil
}

// Write sends Telegram's bytes to the client within the credit it gave, waiting for more
// — and for room on the carrier — as it goes.
func (st *webStream) Write(p []byte) (int, error) {
	c := st.c
	c.mu.Lock()
	defer c.mu.Unlock()
	written := 0
	for written < len(p) {
		for !st.closed && !c.dead && (st.sendWin == 0 || c.queued >= webQueueLimit) {
			c.cond.Wait()
		}
		if st.closed || c.dead {
			return written, net.ErrClosed
		}
		n := min(len(p)-written, int(st.sendWin), wfDataChunk)
		c.enqueueLocked(wfData, st.id, p[written:written+n])
		st.sendWin -= uint32(n)
		written += n
	}
	return written, nil
}

// Close aborts the stream; the client is sent CLOSE unless it closed it.
func (st *webStream) Close() error {
	c := st.c
	c.mu.Lock()
	defer c.mu.Unlock()
	c.abortLocked(st)
	return nil
}

func (st *webStream) LocalAddr() net.Addr              { return webAddr("") }
func (st *webStream) RemoteAddr() net.Addr             { return st.c.remote }
func (st *webStream) SetDeadline(time.Time) error      { return nil }
func (st *webStream) SetReadDeadline(time.Time) error  { return nil }
func (st *webStream) SetWriteDeadline(time.Time) error { return nil }

func beUint32(v uint32) []byte { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }

// logWebHost notes a change of the host the WEB lane answers for.
func logWebHost(prev, host string) {
	if prev == host {
		return
	}
	if host == "" {
		slog.Info("mtproto: WEB proxy off")
	} else {
		slog.Info("mtproto: WEB proxy on", "host", host)
	}
}
