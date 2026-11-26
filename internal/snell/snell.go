// Package snell answers Surge's Snell protocol, versions 5 and 6 (github.com/sagernet/
// sing-snell), and hands every tunnel to Xray's internal snell-in VLESS inbound (see
// vlessin), so Xray does the stats, routing, device limits and speed caps as for any
// lane.
//
// A Snell client names nobody: it has a server, a port and a pre-shared key, and the
// key is what the server tries. So each user gets a port of their own (the server's
// base port plus their slot, see model.SnellPort) with their UUID as the key, and a
// connection on a port is that user's. Every port is its own listener and service; the
// set follows the users Apply is given — a user removed, or given a new UUID, has the
// listener and every connection on it closed.
//
// Version 5 is the classic generation (v4 clients too), with optional http or tls
// obfuscation and no QUIC proxy mode; version 6 has its shaping mode (default or
// unshaped — unsafe-raw has no key, so no user, and is not offered).
package snell

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/Shu1t3/rospanel-shu1t3/internal/snell/upstream/snellv5"
	"github.com/Shu1t3/rospanel-shu1t3/internal/tuning"
	"github.com/Shu1t3/rospanel-shu1t3/internal/vlessin"
)

// Generations, obfuscations (v5) and modes (v6) the lane runs.
const (
	V5 = 5
	V6 = 6

	ObfsNone = "none"
	ObfsHTTP = "http"
	ObfsTLS  = "tls"

	ModeDefault  = "default"
	ModeUnshaped = "unshaped"
)

// Config is how every port of the lane answers. A zero Version is off.
type Config struct {
	Version int
	Obfs    string // v5
	Mode    string // v6
}

// User is one account the lane lets in: Email ("u<id>") names them in Xray, UUID is
// their key and the VLESS id the tunnel enters Xray with, Port is theirs alone.
type User struct {
	Email string
	UUID  string
	Port  int
}

// handshakeTimeout bounds how long a new connection may stay silent before its request.
// Long on purpose: a Surge or Shadowrocket v6 client sends the request with the first
// bytes the app writes (early data), so a socket an app opened ahead of time — a
// browser warming one up — says nothing until it is used. Cut sooner, it is dead when
// the app comes to it. maxConnsPerPort bounds what silent connections can hold.
var handshakeTimeout = 5 * time.Minute

const (
	// maxConnsPerPort bounds the connections one port holds open; a Snell client keeps
	// a small pool of them.
	maxConnsPerPort = 512
	// errListMax bounds how many failed ports an error names.
	errListMax = 5
)

// service is snellv5.Service or snellv6.Service.
type service interface {
	NewConnection(ctx context.Context, conn net.Conn, source M.Socksaddr, onClose N.CloseHandlerFunc) error
}

// Server is the Snell lane. The zero value is not usable; see New.
type Server struct {
	inner atomic.Pointer[string] // snell-in's address
	salt  *snellv5.SaltReplayCache

	mu      sync.Mutex
	cfg     Config
	closed  bool
	ports   map[int]*port // wanted, listening or not
	perUser map[string]int
}

// New returns a server that hands its tunnels to the snell-in inbound at inner: an
// abstract unix socket ("@name") or a loopback "host:port". It listens nowhere until
// Apply.
func New(inner string) *Server {
	s := &Server{salt: snellv5.NewSaltReplayCache(), ports: map[int]*port{}, perUser: map[string]int{}}
	s.inner.Store(&inner)
	return s
}

// port is one user's listener and the connections it accepted.
type port struct {
	user User
	id   [16]byte
	svc  service

	mu     sync.Mutex
	ln     net.Listener // nil while it could not listen
	err    error
	conns  map[net.Conn]struct{}
	closed bool

	warnedAt time.Time // the last line warn logged
	muted    int       // lines warn left out since
}

// Apply makes the lane answer users as cfg says, and stops it for anyone no longer
// among them: their listener and connections are closed. A changed cfg restarts every
// port; a user's port, UUID or email changed restarts theirs. addr is where snell-in
// listens in the same config; "" keeps the address the lane has. The error names the
// ports that could not listen; those are tried again by Retry.
func (s *Server) Apply(cfg Config, addr string, users []User) error {
	want := map[int]User{}
	if cfg.Version != 0 {
		for _, u := range users {
			if _, ok := vlessin.ParseUUID(u.UUID); !ok || u.Email == "" || u.Port <= 0 || u.Port > 65535 {
				continue
			}
			if _, dup := want[u.Port]; !dup {
				want[u.Port] = u
			}
		}
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	if addr != "" {
		s.inner.Store(&addr)
	}
	reset := cfg != s.cfg
	s.cfg = cfg
	// Closed before anything starts: a user's new listener takes the port of the old.
	for n, p := range s.ports {
		if u, ok := want[n]; !ok || reset || u != p.user {
			p.close()
			delete(s.ports, n)
		}
	}
	for n, u := range want {
		p := s.ports[n]
		if p == nil {
			var err error
			if p, err = s.newPort(cfg, u); err != nil {
				continue // the user's key is refused (too short): no port for them
			}
			s.ports[n] = p
		}
		p.start(s)
	}
	err := s.errLocked()
	s.mu.Unlock()
	return err
}

// Retry starts the ports that could not listen (taken, say) — what Apply would do,
// without waiting for the next change to call it.
func (s *Server) Retry() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	for _, p := range s.ports {
		p.start(s)
	}
	return s.errLocked()
}

// errLocked names the ports that do not listen, or is nil.
func (s *Server) errLocked() error {
	var failed []int
	var first error
	for n, p := range s.ports {
		p.mu.Lock()
		if p.ln == nil && p.err != nil {
			failed = append(failed, n)
			if first == nil {
				first = p.err
			}
		}
		p.mu.Unlock()
	}
	if len(failed) == 0 {
		return nil
	}
	sort.Ints(failed)
	names := make([]string, 0, min(len(failed), errListMax))
	for _, n := range failed[:min(len(failed), errListMax)] {
		names = append(names, strconv.Itoa(n))
	}
	if len(failed) > errListMax {
		names = append(names, "…")
	}
	return fmt.Errorf("snell: %d of %d ports could not listen (%s): %w", len(failed), len(s.ports), strings.Join(names, ", "), first)
}

// Close stops the lane for good and ends every connection.
func (s *Server) Close() {
	s.mu.Lock()
	s.closed = true
	ports := s.ports
	s.ports = map[int]*port{}
	s.mu.Unlock()
	for _, p := range ports {
		p.close()
	}
}

// Listening is how many ports listen now.
func (s *Server) Listening() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, p := range s.ports {
		p.mu.Lock()
		if p.ln != nil {
			n++
		}
		p.mu.Unlock()
	}
	return n
}

// Users is how many accounts the lane lets in.
func (s *Server) Users() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.ports)
}

// Open is how many connections are open on the lane's ports.
func (s *Server) Open() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, p := range s.ports {
		p.mu.Lock()
		n += len(p.conns)
		p.mu.Unlock()
	}
	return n
}

// newPort builds u's service as cfg says; it does not listen yet.
func (s *Server) newPort(cfg Config, u User) (*port, error) {
	id, _ := vlessin.ParseUUID(u.UUID)
	p := &port{user: u, id: id, conns: map[net.Conn]struct{}{}}
	h := handler{s: s, p: p}
	switch cfg.Version {
	case V5:
		mode, err := snell.ParseObfsMode(obfsOr(cfg.Obfs))
		if err != nil {
			return nil, err
		}
		svc, err := snellv5.NewService(snellv5.ServiceOptions{PSK: []byte(u.UUID), ObfsMode: mode, Handler: h, SaltCache: s.salt})
		if err != nil {
			return nil, err
		}
		p.svc = svc
	case V6:
		mode, err := snellv6.ParseMode(modeOr(cfg.Mode))
		if err != nil {
			return nil, err
		}
		svc, err := snellv6.NewService(snellv6.ServerOptions{PSK: []byte(u.UUID), Mode: mode, Handler: h})
		if err != nil {
			return nil, err
		}
		p.svc = svc
	default:
		return nil, fmt.Errorf("snell: unknown version %d", cfg.Version)
	}
	return p, nil
}

// obfsOr is a v5 obfuscation the library knows, none for anything else.
func obfsOr(v string) string {
	switch v {
	case ObfsHTTP, ObfsTLS:
		return v
	}
	return ObfsNone
}

// modeOr is a v6 mode the lane runs, default for anything else (unsafe-raw included).
func modeOr(v string) string {
	if v == ModeUnshaped {
		return v
	}
	return ModeDefault
}

// start listens on the port if it does not yet. The caller holds s.mu.
func (p *port) start(s *Server) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.ln != nil {
		return
	}
	lc := tuning.TCPListenConfig()
	ln, err := lc.Listen(context.Background(), "tcp", ":"+strconv.Itoa(p.user.Port))
	if err != nil {
		p.err = err
		return
	}
	p.ln, p.err = ln, nil
	go p.acceptLoop(s, ln)
}

// close stops the port's listener and ends its connections.
func (p *port) close() {
	p.mu.Lock()
	p.closed = true
	ln := p.ln
	p.ln = nil
	conns := p.conns
	p.conns = map[net.Conn]struct{}{}
	p.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	for c := range conns {
		_ = c.Close()
	}
}

// acceptLoop takes the port's connections until its listener is closed. Anything else
// (out of file descriptors under a flood) is waited out, as net/http does.
func (p *port) acceptLoop(s *Server, ln net.Listener) {
	var delay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			time.Sleep(delay)
			continue
		}
		delay = 0
		if !p.track(c) {
			_ = c.Close()
			continue
		}
		go p.serve(c)
	}
}

// track holds c among the port's connections, if the port is open and has room.
func (p *port) track(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || len(p.conns) >= maxConnsPerPort {
		return false
	}
	p.conns[c] = struct{}{}
	return true
}

func (p *port) untrack(c net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.conns, c)
}

type rawConnKey struct{}

// serve runs one connection through the service. The handler carries each request
// before it returns, so the connection is done with when the service is.
func (p *port) serve(c net.Conn) {
	defer func() {
		_ = c.Close()
		p.untrack(c)
	}()
	// The address first: behind a PROXY-protocol listener reading it reads the header,
	// which clears a deadline set before it.
	source := M.SocksaddrFromNet(c.RemoteAddr())
	_ = c.SetReadDeadline(time.Now().Add(handshakeTimeout))
	ctx := context.WithValue(context.Background(), rawConnKey{}, c)
	if err := p.svc.NewConnection(ctx, c, source, nil); err != nil && !quiet(err) {
		p.warn("snell: request failed", source, err)
	}
}

// quiet reports whether a connection's end is not worth a line: the client went away
// (a port check that connects and leaves, a pool closing an idle session), a socket
// opened ahead of time was never used (handshakeTimeout), or the port was closed
// under it.
func quiet(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) || errors.Is(err, os.ErrDeadlineExceeded)
}

// warnEvery bounds the lines a port logs: one, then the next after this long with how
// many were left out — a scan or a client with the wrong key must not flood the log.
const warnEvery = 30 * time.Second

// warn logs why a request on p failed, at most once per warnEvery.
func (p *port) warn(msg string, source M.Socksaddr, err error) {
	p.mu.Lock()
	now := time.Now()
	if now.Sub(p.warnedAt) < warnEvery {
		p.muted++
		p.mu.Unlock()
		return
	}
	muted := p.muted
	p.warnedAt, p.muted = now, 0
	p.mu.Unlock()
	args := []any{"user", p.user.Email, "port", p.user.Port, "from", source.Addr.String(), "err", err}
	if muted > 0 {
		args = append(args, "muted", muted)
	}
	slog.Warn(msg, args...)
}

// handshakeDone lifts the request deadline of the connection a request came on: a
// tunnel, or a pooled connection waiting for the next one, lives on.
func handshakeDone(ctx context.Context) {
	if c, ok := ctx.Value(rawConnKey{}).(net.Conn); ok {
		_ = c.SetReadDeadline(time.Time{})
	}
}

// handler carries a port's requests into Xray as its user.
type handler struct {
	s *Server
	p *port
}

func (h handler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	handshakeDone(ctx)
	err := h.s.relayTCP(h.p, conn, source, destination)
	if err != nil && !quiet(err) {
		h.p.warn("snell: tunnel to "+destination.String()+" failed", source, err)
	}
	if onClose != nil {
		onClose(err)
	}
}

func (h handler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	handshakeDone(ctx)
	err := h.s.relayUDP(h.p, conn, source)
	_ = conn.Close()
	if onClose != nil {
		onClose(err)
	}
}
