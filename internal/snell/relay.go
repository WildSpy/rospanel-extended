package snell

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/Shu1t3/rospanel-shu1t3/internal/vlessin"
)

const (
	dialTimeout = 5 * time.Second
	// maxConnsPerUser bounds a user's open connections to Xray.
	maxConnsPerUser = 1024
	// maxUDPDests bounds the destinations one UDP tunnel keeps a connection to Xray
	// for; past it the one quiet longest is closed.
	maxUDPDests = 64
	// halfCloseWait is how long a tunnel whose download has ended waits for the client
	// to end its upload — on a pooled connection it says so with a zero chunk — before
	// the connection is cut.
	halfCloseWait = 30 * time.Second
)

// udpIdle ends a UDP tunnel nothing has crossed for this long.
var udpIdle = 5 * time.Minute

var (
	errTooManyConns = errors.New("snell: too many open tunnels for this user")
	errBadTarget    = errors.New("snell: bad destination")
	errXrayRefused  = errors.New("snell: refused by Xray")
)

// target is a destination as VLESS addresses it.
func target(d M.Socksaddr) (string, uint16) {
	if d.Port == 0 {
		return "", 0
	}
	if d.IsFqdn() {
		if len(d.Fqdn) > 255 {
			return "", 0
		}
		return d.Fqdn, d.Port
	}
	if !d.Addr.IsValid() {
		return "", 0
	}
	return d.Addr.Unmap().String(), d.Port
}

// dialXray opens a VLESS connection on snell-in as p's user: the PROXY line naming the
// client, then the request header.
func (s *Server) dialXray(p *port, source M.Socksaddr, cmd byte, host string, port uint16) (net.Conn, error) {
	email := p.user.Email
	if !s.reserve(email) {
		return nil, errTooManyConns
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	inner := *s.inner.Load()
	raw, err := (&net.Dialer{}).DialContext(ctx, vlessin.Network(inner), inner)
	cancel()
	if err != nil {
		s.release(email)
		return nil, err
	}
	conn := &xrayConn{Conn: raw, release: func() { s.release(email) }}
	req := vlessin.ProxyHeader(source.String())
	req = vlessin.AppendRequest(req, p.id, cmd, host, port)
	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// xrayConn gives its place in the user's count back once, on the first Close.
type xrayConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *xrayConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func (c *xrayConn) CloseWrite() error { return closeWrite(c.Conn) }

func closeWrite(c net.Conn) error {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// relayTCP carries one TCP tunnel to destination. A refusal is answered as Snell
// answers one (an error reply); a tunnel that ends cleanly ends each way with a
// half-close, which keeps a pooled (reuse) connection for the client's next request.
func (s *Server) relayTCP(p *port, conn net.Conn, source, destination M.Socksaddr) error {
	host, dport := target(destination)
	if host == "" {
		return N.ReportHandshakeFailure(conn, errBadTarget)
	}
	xc, err := s.dialXray(p, source, vlessin.CmdTCP, host, dport)
	if err != nil {
		return N.ReportHandshakeFailure(conn, err)
	}
	defer xc.Close()
	up := make(chan error, 1)
	go func() {
		_, err := io.Copy(xc, conn)
		_ = closeWrite(xc)
		up <- err
	}()
	if !vlessin.ReadResponse(xc) {
		_ = N.ReportHandshakeFailure(conn, errXrayRefused)
		_ = conn.Close()
		_ = xc.Close()
		<-up
		return errXrayRefused
	}
	if _, err := io.Copy(conn, xc); err != nil {
		_ = conn.Close()
		_ = xc.Close()
		<-up
		return err
	}
	_ = closeWrite(conn)
	t := time.NewTimer(halfCloseWait)
	defer t.Stop()
	select {
	case err := <-up:
		return err
	case <-t.C:
		_ = conn.Close()
		_ = xc.Close()
		<-up
		return nil
	}
}

// udpDest is one destination of a UDP tunnel.
type udpDest struct {
	conn net.Conn
	addr M.Socksaddr
	used uint64
	dead atomic.Bool
}

// relayUDP carries a UDP tunnel: packets go out on one VLESS UDP connection per
// destination, replies come back addressed from it. It ends after udpIdle with nothing
// either way, or when the client ends it.
func (s *Server) relayUDP(p *port, pc N.PacketConn, source M.Socksaddr) error {
	var writeMu sync.Mutex
	dests := map[string]*udpDest{}
	var wg sync.WaitGroup
	idle := time.AfterFunc(udpIdle, func() { _ = pc.Close() })
	defer func() {
		idle.Stop()
		_ = pc.Close()
		for _, d := range dests {
			_ = d.conn.Close()
		}
		wg.Wait()
	}()
	var seq uint64
	out := make([]byte, 0, 2+1500)
	for {
		b := buf.NewPacket()
		dest, err := pc.ReadPacket(b)
		if err != nil {
			b.Release()
			return nil
		}
		idle.Reset(udpIdle)
		host, dport := target(dest)
		if host == "" || b.Len() > 0xffff {
			b.Release()
			continue
		}
		key := net.JoinHostPort(host, strconv.Itoa(int(dport)))
		d := dests[key]
		if d != nil && d.dead.Load() {
			_ = d.conn.Close()
			delete(dests, key)
			d = nil
		}
		if d == nil {
			if len(dests) >= maxUDPDests {
				evictIdlest(dests)
			}
			xc, err := s.dialXray(p, source, vlessin.CmdUDP, host, dport)
			if err != nil {
				b.Release()
				continue // this packet is lost, as UDP may lose it
			}
			d = &udpDest{conn: xc, addr: dest}
			dests[key] = d
			wg.Add(1)
			go func() {
				defer wg.Done()
				udpReplies(d, pc, &writeMu, func() { idle.Reset(udpIdle) })
			}()
		}
		seq++
		d.used = seq
		out = binary.BigEndian.AppendUint16(out[:0], uint16(b.Len()))
		out = append(out, b.Bytes()...)
		b.Release()
		if _, err := d.conn.Write(out); err != nil {
			_ = d.conn.Close()
			delete(dests, key)
		}
	}
}

func evictIdlest(dests map[string]*udpDest) {
	var key string
	var idlest *udpDest
	for k, d := range dests {
		if idlest == nil || d.used < idlest.used {
			key, idlest = k, d
		}
	}
	if idlest != nil {
		_ = idlest.conn.Close()
		delete(dests, key)
	}
}

// udpReplies copies one destination's packets back to the client; each keeps the
// tunnel from idling out.
func udpReplies(d *udpDest, pc N.PacketConn, writeMu *sync.Mutex, alive func()) {
	defer d.dead.Store(true)
	if !vlessin.ReadResponse(d.conn) {
		return
	}
	// The client's packet writer seals in place: room before and after the payload.
	front, rear := N.CalculateFrontHeadroom(pc), N.CalculateRearHeadroom(pc)
	var hdr [2]byte
	for {
		if _, err := io.ReadFull(d.conn, hdr[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		b := buf.NewSize(front + n + rear)
		b.Resize(front, 0)
		if _, err := b.ReadFullFrom(d.conn, n); err != nil {
			b.Release()
			return
		}
		writeMu.Lock()
		err := pc.WritePacket(b, d.addr) // takes the buffer
		writeMu.Unlock()
		if err != nil {
			return
		}
		alive()
	}
}

// reserve takes a place in a user's count of open connections to Xray, if one is free.
func (s *Server) reserve(email string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perUser[email] >= maxConnsPerUser {
		return false
	}
	s.perUser[email]++
	return true
}

func (s *Server) release(email string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perUser[email] <= 1 {
		delete(s.perUser, email)
		return
	}
	s.perUser[email]--
}
