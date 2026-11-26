package snell

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	ssnell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/Shu1t3/rospanel-shu1t3/internal/vlessin"
)

const (
	uuidA = "5783a3e7-e373-51cd-8642-c83782b807c5"
	uuidB = "0f9a8c64-9e3b-4b8e-9a49-2b1c3d4e5f60"
)

// fakeXray is snell-in: it reads the PROXY line and the VLESS request, records whose
// id came, answers, and echoes — a TCP stream as it is, UDP as length-framed packets.
type fakeXray struct {
	ln  net.Listener
	mu  sync.Mutex
	ids [][16]byte
}

func newFakeXray(t *testing.T) *fakeXray {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeXray{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeXray) addr() string { return f.ln.Addr().String() }

func (f *fakeXray) seen() [][16]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][16]byte(nil), f.ids...)
}

func (f *fakeXray) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	if _, err := r.ReadString('\n'); err != nil { // PROXY TCP4 …\r\n
		return
	}
	var hdr [1 + 16 + 1 + 1 + 2 + 1]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return
	}
	var id [16]byte
	copy(id[:], hdr[1:17])
	cmd := hdr[18]
	switch hdr[21] {
	case 1:
		_, _ = io.CopyN(io.Discard, r, 4)
	case 3:
		_, _ = io.CopyN(io.Discard, r, 16)
	case 2:
		n, _ := r.ReadByte()
		_, _ = io.CopyN(io.Discard, r, int64(n))
	}
	f.mu.Lock()
	f.ids = append(f.ids, id)
	f.mu.Unlock()
	if _, err := c.Write([]byte{0, 0}); err != nil {
		return
	}
	if cmd == vlessin.CmdTCP {
		_, _ = io.Copy(c, r)
		return
	}
	var l [2]byte
	for {
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return
		}
		p := make([]byte, 2+int(binary.BigEndian.Uint16(l[:])))
		copy(p, l[:])
		if _, err := io.ReadFull(r, p[2:]); err != nil {
			return
		}
		if _, err := c.Write(p); err != nil {
			return
		}
	}
}

func freePorts(t *testing.T, n int) []int {
	t.Helper()
	var out []int
	var lns []net.Listener
	for range n {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		lns = append(lns, ln)
		out = append(out, ln.Addr().(*net.TCPAddr).Port)
	}
	for _, ln := range lns {
		ln.Close()
	}
	return out
}

// method is a Snell client of cfg's version on psk.
func method(t *testing.T, cfg Config, psk string) ssnell.Method {
	t.Helper()
	switch cfg.Version {
	case V5:
		mode, err := ssnell.ParseObfsMode(obfsOr(cfg.Obfs))
		if err != nil {
			t.Fatal(err)
		}
		c, err := snellv4.NewClient(snellv4.ClientOptions{PSK: []byte(psk), ObfsMode: mode, ObfsHost: "www.bing.com"})
		if err != nil {
			t.Fatal(err)
		}
		return c
	default:
		mode, err := snellv6.ParseMode(modeOr(cfg.Mode))
		if err != nil {
			t.Fatal(err)
		}
		c, err := snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(psk), Mode: mode})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
}

func dial(t *testing.T, port int) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return c
}

// echoTCP opens a tunnel on port and checks what it sends comes back, then ends it.
func echoTCP(t *testing.T, m ssnell.Method, port int) error {
	t.Helper()
	conn, err := m.DialConn(dial(t, port), M.ParseSocksaddrHostPort("example.com", 80))
	if err != nil {
		return err
	}
	msg := bytes.Repeat([]byte("snell!"), 20000)
	go func() {
		_, _ = conn.Write(msg)
		_ = N.CloseWrite(conn)
	}()
	got, err := io.ReadAll(conn)
	if err != nil {
		return err
	}
	if !bytes.Equal(got, msg) {
		return errors.New("echo differs: " + strconv.Itoa(len(got)) + " bytes back")
	}
	return nil
}

func TestTCPAndUDPEveryVersion(t *testing.T) {
	x := newFakeXray(t)
	for _, cfg := range []Config{
		{Version: V5, Obfs: ObfsNone},
		{Version: V5, Obfs: ObfsHTTP},
		{Version: V5, Obfs: ObfsTLS},
		{Version: V6, Mode: ModeDefault},
		{Version: V6, Mode: ModeUnshaped},
	} {
		t.Run(strconv.Itoa(cfg.Version)+"-"+cfg.Obfs+cfg.Mode, func(t *testing.T) {
			ports := freePorts(t, 2)
			s := New(x.addr())
			defer s.Close()
			if err := s.Apply(cfg, "", []User{{Email: "u1", UUID: uuidA, Port: ports[0]}, {Email: "u2", UUID: uuidB, Port: ports[1]}}); err != nil {
				t.Fatal(err)
			}
			if err := echoTCP(t, method(t, cfg, uuidA), ports[0]); err != nil {
				t.Fatalf("user 1: %v", err)
			}
			if err := echoTCP(t, method(t, cfg, uuidB), ports[1]); err != nil {
				t.Fatalf("user 2: %v", err)
			}
			ids := x.seen()
			a, _ := vlessin.ParseUUID(uuidA)
			b, _ := vlessin.ParseUUID(uuidB)
			if len(ids) < 2 || ids[len(ids)-2] != a || ids[len(ids)-1] != b {
				t.Fatalf("Xray saw the wrong users")
			}
			// Another user's key on this port gets nothing.
			if err := echoTCP(t, method(t, cfg, uuidB), ports[0]); err == nil {
				t.Fatal("user 2's key opened user 1's port")
			}

			pc, err := method(t, cfg, uuidA).DialPacketConn(dial(t, ports[0]))
			if err != nil {
				t.Fatal(err)
			}
			to := &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53}
			if _, err := pc.WriteTo([]byte("ping"), to); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 64)
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				t.Fatal(err)
			}
			if string(buf[:n]) != "ping" || from.String() != to.String() {
				t.Fatalf("udp: %q from %v", buf[:n], from)
			}
		})
	}
}

func TestApplyClosesRemovedAndRekeyed(t *testing.T) {
	x := newFakeXray(t)
	ports := freePorts(t, 1)
	cfg := Config{Version: V6}
	s := New(x.addr())
	defer s.Close()
	if err := s.Apply(cfg, "", []User{{Email: "u1", UUID: uuidA, Port: ports[0]}}); err != nil {
		t.Fatal(err)
	}
	if s.Listening() != 1 {
		t.Fatal("not listening")
	}
	// An open tunnel is cut when the user's UUID changes, and the old key stops working.
	conn, err := method(t, cfg, uuidA).DialConn(dial(t, ports[0]), M.ParseSocksaddrHostPort("example.com", 80))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	one := make([]byte, 1)
	if _, err := io.ReadFull(conn, one); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(cfg, "", []User{{Email: "u1", UUID: uuidB, Port: ports[0]}}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(conn); err == nil {
		// io.ReadAll returns nil at EOF; either way the tunnel must have ended.
		t.Log("tunnel ended")
	}
	if err := echoTCP(t, method(t, cfg, uuidA), ports[0]); err == nil {
		t.Fatal("the old UUID still works")
	}
	if err := echoTCP(t, method(t, cfg, uuidB), ports[0]); err != nil {
		t.Fatalf("new UUID: %v", err)
	}
	// Removed: the port closes.
	if err := s.Apply(cfg, "", nil); err != nil {
		t.Fatal(err)
	}
	if s.Listening() != 0 {
		t.Fatal("still listening")
	}
	if c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(ports[0]), time.Second); err == nil {
		c.Close()
		t.Fatal("port still open")
	}
}

func TestApplyReportsTakenPortAndRetries(t *testing.T) {
	x := newFakeXray(t)
	taken, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	p := taken.Addr().(*net.TCPAddr).Port
	s := New(x.addr())
	defer s.Close()
	err = s.Apply(Config{Version: V5}, "", []User{{Email: "u1", UUID: uuidA, Port: p}})
	if err == nil || s.Listening() != 0 {
		t.Fatalf("a taken port: err %v, listening %d", err, s.Listening())
	}
	taken.Close()
	if err := s.Retry(); err != nil || s.Listening() != 1 {
		t.Fatalf("retry: err %v, listening %d", err, s.Listening())
	}
}
