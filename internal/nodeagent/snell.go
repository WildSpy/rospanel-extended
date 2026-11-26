package nodeagent

import (
	"fmt"
	"strings"

	"github.com/Shu1t3/rospanel-shu1t3/internal/hostfw"
	"github.com/Shu1t3/rospanel-shu1t3/internal/model"
	"github.com/Shu1t3/rospanel-shu1t3/internal/nodeapi"
	"github.com/Shu1t3/rospanel-shu1t3/internal/snell"
	"github.com/Shu1t3/rospanel-shu1t3/internal/xray"
)

// snellErrMax bounds the listener error reported to the panel.
const snellErrMax = 300

// snellLane is the Snell config and users the panel's state asks for: snell-in's
// clients in cfg, each on the port of their slot. A port Xray or the TLS front holds is
// left out, and said in the error.
func snellLane(cfg []byte, st *nodeapi.SnellState, front int) (snell.Config, []snell.User, string, error) {
	clients, addr := xray.SnellClientsRaw(cfg)
	if st == nil || (st.Version != snell.V5 && st.Version != snell.V6) {
		return snell.Config{}, nil, addr, nil
	}
	conf := snell.Config{Version: st.Version, Obfs: st.Obfs, Mode: st.Mode}
	taken := xray.TCPListenerPortsRaw(cfg)
	users := make([]snell.User, 0, len(clients))
	var clash []string
	for _, c := range clients {
		p := model.SnellPortFor(st.PortBase, st.Slots[c.Email])
		if p == 0 {
			continue
		}
		if tag, ok := taken[p]; ok {
			clash = append(clash, fmt.Sprintf("%d (%s)", p, tag))
			continue
		}
		if p == front {
			clash = append(clash, fmt.Sprintf("%d (TLS front)", p))
			continue
		}
		users = append(users, snell.User{Email: c.Email, UUID: c.ID, Port: p})
	}
	var err error
	if len(clash) > 0 {
		err = fmt.Errorf("snell: ports held by Xray: %s; move the Snell base port", strings.Join(clash, ", "))
	}
	return conf, users, addr, err
}

// snellHostPorts is the range the node's Snell users take, for its firewall.
func snellHostPorts(st *nodeapi.SnellState) []hostfw.Port {
	if st == nil {
		return nil
	}
	lo, hi := 0, 0
	for _, slot := range st.Slots {
		p := model.SnellPortFor(st.PortBase, slot)
		if p == 0 {
			continue
		}
		if lo == 0 || p < lo {
			lo = p
		}
		hi = max(hi, p)
	}
	if lo == 0 {
		return nil
	}
	return []hostfw.Port{{Proto: "tcp", From: lo, To: hi}}
}

// syncSnell puts the node's Snell lane where the panel wants it, with snell-in's
// clients from the config just applied; that closes the ports of anyone it no longer
// holds. Nil-safe for an Agent built without one (tests).
func (a *Agent) syncSnell(cfg []byte, st *nodeapi.SnellState) {
	if a.snell == nil {
		return
	}
	conf, users, addr, err := snellLane(cfg, st, int(a.frontPort.Load()))
	a.snellMu.Lock()
	defer a.snellMu.Unlock()
	if applyErr := a.snell.Apply(conf, addr, users); applyErr != nil {
		err = applyErr
	}
	a.snellErr.Store(clipErr(err, snellErrMax))
}

// clipErr is err's text cut to n, "" for none.
func clipErr(err error, n int) *string {
	msg := ""
	if err != nil {
		if msg = err.Error(); len(msg) > n {
			msg = msg[:n]
		}
	}
	return &msg
}

// snellError is the lane's last error, for the next sync.
func (a *Agent) snellError() string {
	if p := a.snellErr.Load(); p != nil {
		return *p
	}
	return ""
}

// retrySnell starts the ports the last sync could not (taken, say), so the node's
// report says how it stands now. A port Xray holds stays as it is until the panel moves
// the range.
func (a *Agent) retrySnell() {
	e := a.snellError()
	if a.snell == nil || e == "" || strings.Contains(e, "held by Xray") {
		return
	}
	a.snellMu.Lock()
	defer a.snellMu.Unlock()
	a.snellErr.Store(clipErr(a.snell.Retry(), snellErrMax))
}
