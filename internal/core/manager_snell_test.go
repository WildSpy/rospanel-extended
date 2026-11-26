package core

import (
	"strings"
	"testing"

	"github.com/Shu1t3/rospanel-shu1t3/internal/model"
	"github.com/Shu1t3/rospanel-shu1t3/internal/xray"
)

func TestResolveSnell(t *testing.T) {
	cur := &model.Settings{SnellVersion: 5, SnellObfs: "none", SnellMode: "default", SnellPortBase: 61000, SnellObfsHost: "kept.example"}
	held := model.NewReservedPorts()
	held.HoldTCP(40010, "MTProto")

	v, obfs, host, mode, base, err := resolveSnell(0, "", nil, "", 0, cur, true, held, 3)
	if err != nil || v != 5 || obfs != "none" || host != "kept.example" || mode != "default" || base != 61000 {
		t.Fatalf("keep: %d %q %q %q %d %v", v, obfs, host, mode, base, err)
	}
	empty := ""
	if _, _, host, _, _, err := resolveSnell(6, "", &empty, "unshaped", 0, cur, true, held, 3); err != nil || host != "" {
		t.Fatalf("clear the host: %q %v", host, err)
	}
	for name, c := range map[string]struct {
		version     int
		obfs, mode  string
		host        string
		base, slots int
		code        string
	}{
		"version":    {version: 4, code: "err.snellVersion"},
		"obfs":       {obfs: "shadow-tls", code: "err.snellObfs"},
		"raw mode":   {mode: "unsafe-raw", code: "err.snellMode"},
		"host":       {host: "not a host", code: "err.snellObfsHost"},
		"too low":    {base: 80, code: "err.snellPortBase"},
		"past 65535": {base: 65000, slots: 600, code: "err.snellPortBase"},
		"taken":      {base: 40000, slots: 20, code: "err.snellPortTaken"},
	} {
		h := c.host
		_, _, _, _, _, err := resolveSnell(c.version, c.obfs, &h, c.mode, c.base, cur, true, held, c.slots)
		if err == nil || !strings.Contains(errCode(err), c.code) {
			t.Errorf("%s: %v, want %s", name, err, c.code)
		}
	}
	// A taken port in the range is the lane's concern only while it is on.
	if _, _, _, _, _, err := resolveSnell(0, "", nil, "", 40000, cur, false, held, 20); err != nil {
		t.Fatalf("off: %v", err)
	}
}

func TestSnellUsersPortsAndXrayClash(t *testing.T) {
	clients := []xray.VLESSClient{{Email: "u1", ID: "a"}, {Email: "u2", ID: "b"}, {Email: "u3", ID: "c"}}
	slots := map[string]int{"u1": 1, "u2": 3} // u3 has none yet
	users, err := snellUsers(40000, clients, slots, map[int]string{40002: "vless-in"})
	if len(users) != 1 || users[0].Port != 40000 || users[0].Email != "u1" {
		t.Fatalf("users: %+v", users)
	}
	if err == nil || !strings.Contains(err.Error(), "40002 (vless-in)") {
		t.Fatalf("clash not named: %v", err)
	}
	if r := snellRange(users); len(r) != 1 || r[0].From != 40000 || r[0].To != 40000 || r[0].Proto != "tcp" {
		t.Fatalf("range: %+v", r)
	}
}
