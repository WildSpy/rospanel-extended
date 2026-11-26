package link

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Shu1t3/rospanel-shu1t3/internal/model"
)

func TestSnellShadowrocketForm(t *testing.T) {
	u := model.User{ID: 7, UUID: "5783a3e7-e373-51cd-8642-c83782b807c5", SnellSlot: 3}
	set := &model.Settings{Host: "203.0.113.5", SnellEnabled: true, SnellVersion: 5, SnellObfs: "http", SnellPortBase: 40000}
	got := Snell(u, set)
	want := "snell://" + base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:"+u.UUID)) +
		"@203.0.113.5:40002?plugin=obfs-local;obfs%3Dhttp;obfs-host%3Dwww.bing.com;obfs-uri%3D/&version=5&udp=1#SNELL"
	if got != want {
		t.Fatalf("v5 http:\n got %s\nwant %s", got, want)
	}

	set.SnellObfs = "none"
	if got := Snell(u, set); strings.Contains(got, "plugin=") || !strings.Contains(got, "?version=5&udp=1#") {
		t.Fatalf("v5 without obfs: %s", got)
	}

	set.SnellVersion, set.SnellMode, set.Host = 6, "unshaped", "2001:db8::1"
	if got := Snell(u, set); !strings.Contains(got, "@[2001:db8::1]:40002?mode=unshaped&version=6&udp=1#") {
		t.Fatalf("v6 unshaped over IPv6: %s", got)
	}
	set.SnellMode = "default"
	if got := Snell(u, set); strings.Contains(got, "mode=") {
		t.Fatalf("v6 default names its mode: %s", got)
	}

	// No slot yet, or the lane off: no link.
	if SnellOn(set, &model.User{UUID: u.UUID}) {
		t.Fatal("a user with no slot has a Snell link")
	}
	set.SnellEnabled = false
	if SnellOn(set, &u) {
		t.Fatal("a server with Snell off hands it out")
	}
}
