package core

import (
	"strings"
	"testing"

	"github.com/Shu1t3/rospanel-shu1t3/internal/link"
	"github.com/Shu1t3/rospanel-shu1t3/internal/model"
)

// The WEB proxy rides on the server's own domain on 443, beside the fake-TLS port or
// instead of it; a server known by its address alone has none.
func TestMTProtoListenWeb(t *testing.T) {
	t.Parallel()
	base := model.Settings{MTProtoEnabled: true, MTProtoPort: 20000, VLESSPort: 443, Host: "VPN.example.com", MTProtoWeb: true}
	cases := []struct {
		name     string
		edit     func(*model.Settings)
		port     int
		web      string
		fake, wl bool
	}{
		{"both", func(*model.Settings) {}, 20000, "vpn.example.com", true, true},
		{"web only", func(s *model.Settings) { s.MTProtoWebOnly = true }, 0, "vpn.example.com", false, true},
		{"web off", func(s *model.Settings) { s.MTProtoWeb, s.MTProtoWebOnly = false, true }, 20000, "", true, false},
		{"address only", func(s *model.Settings) { s.Host, s.MTProtoWebOnly = "203.0.113.5", true }, 20000, "", true, false},
		{"TLS lane off 443", func(s *model.Settings) { s.VLESSPort = 8443 }, 20000, "", true, false},
		{"lane off", func(s *model.Settings) { s.MTProtoEnabled = false }, 0, "", false, false},
	}
	for _, c := range cases {
		s := base
		c.edit(&s)
		l := MTProtoListen(&s)
		if l.Port != c.port || l.Web != c.web {
			t.Errorf("%s: port %d web %q, want %d %q", c.name, l.Port, l.Web, c.port, c.web)
		}
		if link.MTProtoOn(&s) != c.fake || link.MTProtoWebProxyOn(&s) != c.wl {
			t.Errorf("%s: fake-TLS link %v, WEB link %v; want %v %v", c.name, link.MTProtoOn(&s), link.MTProtoWebProxyOn(&s), c.fake, c.wl)
		}
	}
	s := base
	u := model.User{UUID: "11111111-2222-3333-4444-555555555555"}
	if got := link.MTProtoWebProxy(u, &s); !strings.HasPrefix(got, "tg://webproxy?") || !strings.Contains(got, "server=vpn.example.com") || !strings.Contains(got, "secret=dd") {
		t.Fatalf("WEB link %s", got)
	}
}

func TestResolveMTProtoWeb(t *testing.T) {
	t.Parallel()
	yes, no := true, false
	own := &model.Settings{Host: "vpn.example.com", VLESSPort: 443}
	bare := &model.Settings{Host: "203.0.113.5", VLESSPort: 443}
	if on, only, err := resolveMTProtoWeb(&yes, &yes, false, false, own); err != nil || !on || !only {
		t.Fatalf("on with a domain: %v %v %v", on, only, err)
	}
	if _, _, err := resolveMTProtoWeb(&yes, nil, false, false, bare); err == nil {
		t.Fatal("switched on with no domain")
	}
	if on, only, err := resolveMTProtoWeb(&no, &yes, true, true, bare); err != nil || on || only {
		t.Fatalf("off: %v %v %v", on, only, err)
	}
	if on, only, err := resolveMTProtoWeb(nil, nil, true, true, own); err != nil || !on || !only {
		t.Fatalf("a caller that predates the switches changed them: %v %v %v", on, only, err)
	}
}
