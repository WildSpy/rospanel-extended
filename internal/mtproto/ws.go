package mtproto

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// A WebSocket server (RFC 6455) just large enough for the WEB carrier: binary messages,
// fragmentation, ping/pong and close. Text messages are not part of the carrier and end
// it, as tproxy-server's relay does.

const (
	wsOpCont   = 0x0
	wsOpText   = 0x1
	wsOpBinary = 0x2
	wsOpClose  = 0x8
	wsOpPing   = 0x9
	wsOpPong   = 0xa

	// wsMaxMessage caps one client message: a batch of complete frames. The bridge sends
	// one frame (≤ 1 MiB) per message from the hidden WebView, and the browser fallback a
	// batch tdesktop keeps to 64 KiB DATA frames.
	wsMaxMessage = 4 << 20

	wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

var (
	errWSProtocol = errors.New("mtproto: WebSocket protocol error")
	errWSTooBig   = errors.New("mtproto: WebSocket message too big")
	errWSText     = errors.New("mtproto: WebSocket text message")
)

type wsConn struct {
	c  net.Conn
	br *bufio.Reader

	wmu sync.Mutex // one frame at a time on the wire
}

// headerHasToken reports whether a comma-separated header names token, case-insensitively.
func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// isWebSocketUpgrade reports whether r asks to become an RFC 6455 WebSocket.
func isWebSocketUpgrade(r *http.Request) bool {
	if r.Method != http.MethodGet || r.ProtoMajor != 1 {
		return false
	}
	if !headerHasToken(r.Header, "Upgrade", "websocket") || !headerHasToken(r.Header, "Connection", "upgrade") {
		return false
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		return false
	}
	key, err := base64.StdEncoding.DecodeString(r.Header.Get("Sec-WebSocket-Key"))
	return err == nil && len(key) == 16
}

// wsAccept answers an upgrade request (isWebSocketUpgrade) with protocol as the
// subprotocol, and takes the connection over.
func wsAccept(w http.ResponseWriter, r *http.Request, protocol string) (*wsConn, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("mtproto: connection cannot be taken over")
	}
	c, brw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + wsGUID))
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + base64.StdEncoding.EncodeToString(sum[:]) + "\r\n" +
		"Sec-WebSocket-Protocol: " + protocol + "\r\n\r\n"
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	if _, err := io.WriteString(c, resp); err != nil {
		_ = c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return &wsConn{c: c, br: brw.Reader}, nil
}

// readMessage reads the next binary message, answering pings and the client's close on
// the way. A close, or anything but a binary message, ends the connection (io.EOF for a
// close).
func (ws *wsConn) readMessage() ([]byte, error) {
	var msg []byte
	started := false
	for {
		fin, op, payload, err := ws.readFrame(wsMaxMessage - len(msg))
		if err != nil {
			return nil, err
		}
		switch op {
		case wsOpPing:
			if err := ws.writeFrame(wsOpPong, payload); err != nil {
				return nil, err
			}
			continue
		case wsOpPong:
			continue
		case wsOpClose:
			code := []byte{0x03, 0xe8} // 1000
			if len(payload) >= 2 {
				code = payload[:2]
			}
			_ = ws.writeFrame(wsOpClose, code)
			return nil, io.EOF
		case wsOpText:
			return nil, errWSText
		case wsOpBinary:
			if started {
				return nil, errWSProtocol
			}
			started = true
		case wsOpCont:
			if !started {
				return nil, errWSProtocol
			}
		default:
			return nil, errWSProtocol
		}
		msg = append(msg, payload...)
		if fin {
			return msg, nil
		}
	}
}

// readFrame reads one frame, unmasked; a data frame may carry at most limit bytes.
func (ws *wsConn) readFrame(limit int) (fin bool, op byte, payload []byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(ws.br, h[:]); err != nil {
		return
	}
	fin, op = h[0]&0x80 != 0, h[0]&0x0f
	if h[0]&0x70 != 0 || h[1]&0x80 == 0 { // no extensions were agreed; clients must mask
		return false, 0, nil, errWSProtocol
	}
	n := uint64(h[1] & 0x7f)
	switch n {
	case 126:
		var b [2]byte
		if _, err = io.ReadFull(ws.br, b[:]); err != nil {
			return
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err = io.ReadFull(ws.br, b[:]); err != nil {
			return
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	if op >= 0x8 && (!fin || n > 125) {
		return false, 0, nil, errWSProtocol
	}
	if op < 0x8 && n > uint64(max(limit, 0)) {
		return false, 0, nil, errWSTooBig
	}
	var mask [4]byte
	if _, err = io.ReadFull(ws.br, mask[:]); err != nil {
		return
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(ws.br, payload); err != nil {
		return
	}
	for i := range payload {
		payload[i] ^= mask[i&3]
	}
	return fin, op, payload, nil
}

// writeFrame writes one unmasked, final frame.
func (ws *wsConn) writeFrame(op byte, payload []byte) error {
	var h [10]byte
	h[0] = 0x80 | op
	n := len(payload)
	hl := 2
	switch {
	case n < 126:
		h[1] = byte(n)
	case n <= 0xffff:
		h[1] = 126
		binary.BigEndian.PutUint16(h[2:], uint16(n))
		hl = 4
	default:
		h[1] = 127
		binary.BigEndian.PutUint64(h[2:], uint64(n))
		hl = 10
	}
	ws.wmu.Lock()
	defer ws.wmu.Unlock()
	return ws.writeLocked(h[:hl], payload)
}

func (ws *wsConn) writeLocked(head, payload []byte) error {
	_ = ws.c.SetWriteDeadline(time.Now().Add(webWriteTimeout))
	bufs := net.Buffers{head, payload}
	_, err := bufs.WriteTo(ws.c)
	return err
}

func (ws *wsConn) writeBinary(p []byte) error { return ws.writeFrame(wsOpBinary, p) }

// close sends a close frame with code — unless a write is stuck on the wire, which the
// close below ends — and closes the connection.
func (ws *wsConn) close(code uint16) {
	if ws.wmu.TryLock() {
		_ = ws.c.SetWriteDeadline(time.Now().Add(time.Second))
		_, _ = ws.c.Write([]byte{0x80 | wsOpClose, 2, byte(code >> 8), byte(code)})
		ws.wmu.Unlock()
	}
	_ = ws.c.Close()
}
