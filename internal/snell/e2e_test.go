package snell_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	ssnell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/Shu1t3/rospanel-shu1t3/internal/link"
	"github.com/Shu1t3/rospanel-shu1t3/internal/model"
	"github.com/Shu1t3/rospanel-shu1t3/internal/snell"
	"github.com/Shu1t3/rospanel-shu1t3/internal/xray"
)

// TestAgainstRealXray runs the lane as it runs in the panel: a real Xray with snell-in
// behind it, Snell clients configured from the link the panel hands out, a download and
// a UDP echo through each generation, and the bytes counted under the user in Xray's
// stats. Opt-in: RP_SNELL_E2E_DIR holds xray.
func TestAgainstRealXray(t *testing.T) {
	dir := os.Getenv("RP_SNELL_E2E_DIR")
	if dir == "" {
		t.Skip("RP_SNELL_E2E_DIR not set")
	}
	const uuid, email = "5783a3e7-e373-51cd-8642-c83782b807c5", "u7"
	const n = 8 << 20
	work := t.TempDir()

	target := listenTCP(t)
	go func() {
		_ = http.Serve(target, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(n))
			_, _ = io.CopyN(w, zeros{}, n)
		}))
	}()
	echo, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			k, from, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = echo.WriteTo(buf[:k], from)
		}
	}()

	apiPort := freePort(t)
	listen, port := xray.InnerListen(xray.SnellInnerAddr)
	cfg := map[string]any{
		"log":    map[string]any{"loglevel": "warning"},
		"api":    map[string]any{"tag": "api", "services": []string{"StatsService"}},
		"stats":  map[string]any{},
		"policy": map[string]any{"levels": map[string]any{"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true}}},
		"inbounds": []any{
			map[string]any{"tag": "api", "listen": "127.0.0.1", "port": apiPort, "protocol": "dokodemo-door",
				"settings": map[string]any{"address": "127.0.0.1"}},
			xray.Inbound{
				Tag: xray.TagSnell, Listen: listen, Port: port, Protocol: "vless",
				Settings:       xray.VLESSInboundSettings{Clients: []xray.VLESSClient{{ID: uuid, Email: email}}, Decryption: "none"},
				StreamSettings: &xray.StreamSettings{Network: "tcp", Sockopt: json.RawMessage(`{"acceptProxyProtocol":true}`)},
			},
		},
		"outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{
			"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.1/32"}}}}}},
		"routing": map[string]any{"rules": []any{map[string]any{"inboundTag": []string{"api"}, "outboundTag": "api"}}},
	}
	runJSON(t, exec.Command(filepath.Join(dir, "xray"), "run", "-c"), work, "server.json", cfg)
	waitTCP(t, apiPort)
	if port > 0 {
		waitTCP(t, port)
	}

	base := freePort(t)
	u := model.User{ID: 7, UUID: uuid, SnellSlot: 1}
	for _, c := range []struct {
		set  model.Settings
		conf snell.Config
	}{
		{model.Settings{SnellVersion: 5, SnellObfs: "none"}, snell.Config{Version: 5, Obfs: "none"}},
		{model.Settings{SnellVersion: 5, SnellObfs: "http"}, snell.Config{Version: 5, Obfs: "http"}},
		{model.Settings{SnellVersion: 5, SnellObfs: "tls"}, snell.Config{Version: 5, Obfs: "tls"}},
		{model.Settings{SnellVersion: 6, SnellMode: "default"}, snell.Config{Version: 6, Mode: "default"}},
		{model.Settings{SnellVersion: 6, SnellMode: "unshaped"}, snell.Config{Version: 6, Mode: "unshaped"}},
	} {
		name := fmt.Sprintf("v%d-%s%s", c.conf.Version, c.conf.Obfs, c.conf.Mode)
		t.Run(name, func(t *testing.T) {
			set := c.set
			set.Host, set.SnellEnabled, set.SnellPortBase = "127.0.0.1", true, base
			lane := snell.New(xray.SnellInnerAddr)
			defer lane.Close()
			if err := lane.Apply(c.conf, "", []snell.User{{Email: email, UUID: uuid, Port: set.SnellPort(&u)}}); err != nil {
				t.Fatal(err)
			}
			m, server := clientFromLink(t, link.Snell(u, &set))
			before := userBytes(t, dir, apiPort, email)

			conn, err := m.DialConn(dial(t, server), M.ParseSocksaddr(target.Addr().String()))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			got, err := io.Copy(io.Discard, conn)
			if err != nil || got < n {
				t.Fatalf("download: %d bytes, %v", got, err)
			}

			pc, err := m.DialPacketConn(dial(t, server))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pc.WriteTo([]byte("ping"), echo.LocalAddr()); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 64)
			k, _, err := pc.ReadFrom(buf)
			if err != nil || string(buf[:k]) != "ping" {
				t.Fatalf("udp: %q %v", buf[:k], err)
			}
			pc.Close()

			if after := userBytes(t, dir, apiPort, email); after-before < n {
				t.Fatalf("Xray counted %d bytes for %s, want ≥ %d", after-before, email, n)
			}
		})
	}
}

// clientFromLink is a Snell client set up from what a snell:// link says, as
// Shadowrocket reads it: the key after the method in the base64 userinfo, the version,
// and the obfuscation in the plugin.
func clientFromLink(t *testing.T, raw string) (ssnell.Method, int) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := base64.RawURLEncoding.DecodeString(u.User.Username())
	if err != nil {
		t.Fatal(err)
	}
	_, psk, ok := strings.Cut(string(cred), ":")
	if !ok {
		t.Fatalf("no key in %s", raw)
	}
	port, _ := strconv.Atoi(u.Port())
	// Split by hand: the plugin value holds ";", which url.ParseQuery refuses.
	q := url.Values{}
	for _, kv := range strings.Split(u.RawQuery, "&") {
		k, v, _ := strings.Cut(kv, "=")
		v, err := url.QueryUnescape(v)
		if err != nil {
			t.Fatal(err)
		}
		q.Set(k, v)
	}
	if q.Get("udp") != "1" {
		t.Fatalf("no udp=1 in %s", raw)
	}
	if q.Get("version") == "6" {
		mode, err := snellv6.ParseMode(q.Get("mode"))
		if err != nil {
			t.Fatal(err)
		}
		c, err := snellv6.NewClient(snellv6.ClientOptions{PSK: []byte(psk), Mode: mode})
		if err != nil {
			t.Fatal(err)
		}
		return c, port
	}
	obfs, host := "none", ""
	for _, kv := range strings.Split(q.Get("plugin"), ";") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			switch k {
			case "obfs":
				obfs = v
			case "obfs-host":
				host = v
			}
		}
	}
	mode, err := ssnell.ParseObfsMode(obfs)
	if err != nil {
		t.Fatal(err)
	}
	c, err := snellv4.NewClient(snellv4.ClientOptions{PSK: []byte(psk), ObfsMode: mode, ObfsHost: host})
	if err != nil {
		t.Fatal(err)
	}
	return c, port
}

// userBytes is what Xray has counted for email, up and down.
func userBytes(t *testing.T, dir string, apiPort int, email string) int64 {
	t.Helper()
	out, err := exec.Command(filepath.Join(dir, "xray"), "api", "statsquery",
		"--server=127.0.0.1:"+strconv.Itoa(apiPort), "-pattern", "user>>>"+email+">>>").Output()
	if err != nil {
		t.Fatalf("statsquery: %v", err)
	}
	var doc struct {
		Stat []struct {
			Value json.Number `json:"value"`
		} `json:"stat"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &doc); err != nil {
		t.Fatalf("statsquery: %v: %s", err, out)
	}
	var sum int64
	for _, s := range doc.Stat {
		v, _ := s.Value.Int64()
		sum += v
	}
	return sum
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func runJSON(t *testing.T, cmd *exec.Cmd, work, name string, cfg any) {
	t.Helper()
	b, _ := json.MarshalIndent(cfg, "", " ")
	path := filepath.Join(work, name)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd.Args = append(cmd.Args, path)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
}

func listenTCP(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

func freePort(t *testing.T) int {
	t.Helper()
	ln := listenTCP(t)
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}

func dial(t *testing.T, port int) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	return c
}

func waitTCP(t *testing.T, port int) {
	t.Helper()
	for range 100 {
		if c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port)); err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("nothing listens on %d", port)
}
