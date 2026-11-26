package core

import (
	"fmt"
	"strings"

	"github.com/Shu1t3/rospanel-shu1t3/internal/hostfw"
	"github.com/Shu1t3/rospanel-shu1t3/internal/model"
	"github.com/Shu1t3/rospanel-shu1t3/internal/nodeapi"
	"github.com/Shu1t3/rospanel-shu1t3/internal/snell"
	"github.com/Shu1t3/rospanel-shu1t3/internal/xray"
)

// snellErrMax bounds a listener error kept for the Connections screen.
const snellErrMax = 300

// snellConfig is how a server's settings say its Snell ports answer; off is zero.
func snellConfig(set *model.Settings) snell.Config {
	if !set.SnellEnabled {
		return snell.Config{}
	}
	v := model.SnellVersionOr(set.SnellVersion)
	if v == model.SnellV6 {
		return snell.Config{Version: snell.V6, Mode: model.SnellModeOr(set.SnellMode)}
	}
	return snell.Config{Version: snell.V5, Obfs: model.SnellObfsOr(set.SnellObfs)}
}

// snellUsers are the Snell lane's users — snell-in's clients — each on the port of their
// slot, read from users. One with no slot, a port past 65535, or a port Xray listens on
// is left out; the last is said in the error, as no listener could start there.
func snellUsers(base int, clients []xray.VLESSClient, slots map[string]int, xrayPorts map[int]string) ([]snell.User, error) {
	out := make([]snell.User, 0, len(clients))
	var clash []string
	for _, c := range clients {
		p := model.SnellPortFor(base, slots[c.Email])
		if p == 0 {
			continue
		}
		if tag, taken := xrayPorts[p]; taken {
			clash = append(clash, fmt.Sprintf("%d (%s)", p, tag))
			continue
		}
		out = append(out, snell.User{Email: c.Email, UUID: c.ID, Port: p})
	}
	if len(clash) > 0 {
		return out, fmt.Errorf("snell: ports held by Xray: %s; move the Snell base port", strings.Join(clash, ", "))
	}
	return out, nil
}

// slotsByEmail is each user's Snell slot by their Xray email.
func slotsByEmail(users []model.User) map[string]int {
	out := make(map[string]int, len(users))
	for i := range users {
		if users[i].SnellSlot > 0 {
			out[model.UserEmail(users[i].ID)] = users[i].SnellSlot
		}
	}
	return out
}

// snellRange is the firewall range a lane's users take: base to the highest port.
func snellRange(users []snell.User) []hostfw.Port {
	lo, hi := 0, 0
	for _, u := range users {
		if lo == 0 || u.Port < lo {
			lo = u.Port
		}
		hi = max(hi, u.Port)
	}
	if lo == 0 {
		return nil
	}
	return []hostfw.Port{{Proto: "tcp", From: lo, To: hi}}
}

// syncSnell puts the master's Snell lane where the settings say, with the users of the
// config just put in force (their slots from users); that closes the ports of anyone it
// no longer holds. Ports that cannot listen are reported on the Connections screen and
// logged once per change, and tried again by RetrySnell.
func (m *Manager) syncSnell(set *model.Settings, cfg *xray.Config, users []model.User) {
	if m.snell == nil {
		return
	}
	clients, addr := xray.SnellClients(cfg)
	conf := snellConfig(set)
	var su []snell.User
	var err error
	if conf.Version != 0 {
		su, err = snellUsers(set.SnellPortBase, clients, slotsByEmail(users), xray.TCPListenerPorts(cfg))
	}
	m.snellPorts.Store(&su)
	if applyErr := m.snell.Apply(conf, addr, su); applyErr != nil {
		err = applyErr
	}
	msg := ""
	if err != nil {
		if msg = err.Error(); len(msg) > snellErrMax {
			msg = msg[:snellErrMax]
		}
	}
	if prev := m.snellErr.Swap(&msg); prev == nil || *prev != msg {
		if err != nil {
			logErr("snell: listeners failed", "err", err)
		}
	}
}

// snellHostPorts is the master's Snell range for the host firewall, from its last sync.
func (m *Manager) snellHostPorts() []hostfw.Port {
	if p := m.snellPorts.Load(); p != nil {
		return snellRange(*p)
	}
	return nil
}

// SnellStatus reports how many of the master's Snell ports listen, of how many, and
// the last error.
func (m *Manager) SnellStatus() (listening, users int, lastErr string) {
	if m.snell == nil {
		return 0, 0, ""
	}
	if p := m.snellErr.Load(); p != nil {
		lastErr = *p
	}
	return m.snell.Listening(), m.snell.Users(), lastErr
}

// StopSnell closes the master's Snell lane (shutdown).
func (m *Manager) StopSnell() {
	if m.snell != nil {
		m.snell.Close()
	}
}

// RetrySnell starts the master's Snell ports the last sync could not (taken, say),
// without waiting for the next change. Under applyMu, like the sync.
func (m *Manager) RetrySnell() {
	if m.snell == nil {
		return
	}
	m.applyMu.Lock()
	defer m.applyMu.Unlock()
	if p := m.snellErr.Load(); p == nil || *p == "" || strings.Contains(*p, "held by Xray") {
		return
	}
	msg := ""
	if err := m.snell.Retry(); err != nil {
		if msg = err.Error(); len(msg) > snellErrMax {
			msg = msg[:snellErrMax]
		}
	}
	m.snellErr.Store(&msg)
}

// claimSnell gives every user in users with no Snell slot one, when the server's lane
// is on. users is not changed: when anyone needed a claim, a copy holding it is
// returned and claimed is true, because the users handed in may be the snapshot every
// node shares. ok is false when the claim failed; those users stay off the lane.
func (m *Manager) claimSnell(on bool, users []model.User) (out []model.User, claimed, ok bool) {
	if !on {
		return users, false, true
	}
	var ids []int64
	for i := range users {
		if users[i].SnellSlot == 0 {
			ids = append(ids, users[i].ID)
		}
	}
	if len(ids) == 0 {
		return users, false, true
	}
	got, err := m.store.ClaimSnellSlots(ids)
	if err != nil {
		logErr("snell: user slots", "err", err)
		return users, false, false
	}
	out = append([]model.User(nil), users...)
	for i := range out {
		if s, ok := got[out[i].ID]; ok && out[i].SnellSlot == 0 {
			out[i].SnellSlot = s
		}
	}
	// The shared node inputs hold the users as they were read.
	m.dropNodeInputs()
	return out, true, true
}

// nodeSnellState is a node's Snell lane for its agent: nil when off.
func nodeSnellState(ns *model.Settings, cfg *xray.Config, users []model.User) *nodeapi.SnellState {
	conf := snellConfig(ns)
	if conf.Version == 0 {
		return nil
	}
	st := &nodeapi.SnellState{Version: conf.Version, Obfs: conf.Obfs, Mode: conf.Mode, PortBase: model.SnellPortBaseOr(ns.SnellPortBase)}
	clients, _ := xray.SnellClients(cfg)
	slots := slotsByEmail(users)
	for _, c := range clients {
		if s := slots[c.Email]; s > 0 {
			if st.Slots == nil {
				st.Slots = make(map[string]int, len(clients))
			}
			st.Slots[c.Email] = s
		}
	}
	return st
}

// resolveSnell checks the Snell settings an operator entered for a server and settles
// them: 0, "" and a nil host keep what the server has. held is what else listens on the server;
// none of it may fall in the range the server's users take (maxSlot of them), which
// must also end by 65535.
func resolveSnell(version int, obfs string, obfsHostIn *string, mode string, base int, cur *model.Settings, on bool, held model.ReservedPorts, maxSlot int) (int, string, string, string, int, error) {
	if version == 0 {
		version = cur.SnellVersion
	}
	if version != model.SnellV5 && version != model.SnellV6 {
		return 0, "", "", "", 0, invalidCode("err.snellVersion", "Snell: версия должна быть 5 или 6")
	}
	if obfs == "" {
		obfs = cur.SnellObfs
	}
	if obfs != model.SnellObfsNone && obfs != model.SnellObfsHTTP && obfs != model.SnellObfsTLS {
		return 0, "", "", "", 0, invalidCode("err.snellObfs", "Snell: обфускация должна быть none, http или tls")
	}
	if mode == "" {
		mode = cur.SnellMode
	}
	if mode != model.SnellModeDefault && mode != model.SnellModeUnshaped {
		return 0, "", "", "", 0, invalidCode("err.snellMode", "Snell: режим v6 должен быть default или unshaped")
	}
	obfsHost := cur.SnellObfsHost
	if obfsHostIn != nil {
		obfsHost = *obfsHostIn
	}
	obfsHost = strings.TrimSpace(obfsHost)
	if obfsHost != "" && !realityHostRe.MatchString(obfsHost) {
		return 0, "", "", "", 0, invalidCode("err.snellObfsHost", "Snell: домен обфускации {{value}} не похож на настоящий", map[string]any{"value": obfsHost})
	}
	if base == 0 {
		base = model.SnellPortBaseOr(cur.SnellPortBase)
	}
	span := max(maxSlot, 1)
	if base < 1024 || base+span-1 > 65535 {
		return 0, "", "", "", 0, invalidCode("err.snellPortBase", "Snell: первый порт {{port}} не годится — порты {{port}}–{{last}} должны лежать в 1024–65535", map[string]any{"port": base, "last": base + span - 1})
	}
	if on && held.TCP != nil {
		for p := base; p < base+span; p++ {
			if who, taken := held.OnTCP(p); taken {
				return 0, "", "", "", 0, invalidCode("err.snellPortTaken", "Snell: порт {{port}} из диапазона {{from}}–{{to}} уже занят ({{who}}) — выберите другой первый порт",
					map[string]any{"port": p, "from": base, "to": base + span - 1, "who": who})
			}
		}
	}
	return version, obfs, obfsHost, mode, base, nil
}

// snellHeldOn is what else listens on a server whose settings are set — its lanes and
// custom inbounds — for resolveSnell.
func snellHeldOn(set *model.Settings, custom []model.Inbound) model.ReservedPorts {
	r := withCustomPorts(reservedPorts(set), custom)
	if set.MieruEnabled && set.MieruPort > 0 {
		r.HoldTCP(set.MieruPort, "mieru")
	}
	return r
}
