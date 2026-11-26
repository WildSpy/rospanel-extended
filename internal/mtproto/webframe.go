package mtproto

import (
	"encoding/binary"
	"errors"
)

// The shared relay frame of WEB proxy protocol v1, big-endian:
//
//	type:u8 | stream_id:u24 | length:u32 | payload
//
// A carrier message holds one or more complete frames, never an empty or partial one.

const (
	wfOpen     byte = 0x01 // client → relay, stream > 0, empty
	wfData     byte = 0x02 // both ways, stream > 0, opaque and never empty
	wfClose    byte = 0x03 // both ways, stream > 0, empty: an abort, not a half-close
	wfWindow   byte = 0x04 // both ways, stream > 0, a non-zero u32 credit delta
	wfPing     byte = 0x05 // relay → client, stream 0, an echo token
	wfPong     byte = 0x06 // client → relay, stream 0, the token echoed
	wfHello    byte = 0x10 // client → relay, stream 0, the byte 01
	wfWelcome  byte = 0x11 // relay → client, stream 0, empty, the relay's first frame
	wfAuthChal byte = 0x12 // reserved for relay-auth v2: a protocol error in v1
	wfAuthResp byte = 0x13 // reserved for relay-auth v2
	wfBye      byte = 0x1f // relay → client, stream 0: fails every stream, ends the carrier

	wfHeaderLen = 8
	// wfMaxPayload caps one frame's payload.
	wfMaxPayload = 1 << 20
	// wfMaxBatch caps the frames in one carrier message.
	wfMaxBatch = 4096
	// wfMaxStream is the largest stream id (24 bits).
	wfMaxStream = 1<<24 - 1
	// wfMaxPing caps a PING's (and so a PONG's) payload.
	wfMaxPing = 64
	// wfWindow0 is every stream's implicit credit, each way, never negotiated.
	wfWindow0 = 4 << 20
	// wfDataChunk is the largest DATA the relay sends; tdesktop caps its own the same.
	wfDataChunk = 64 << 10
)

var errWebFrame = errors.New("mtproto: malformed WEB frame batch")

type webFrame struct {
	typ     byte
	stream  uint32
	payload []byte
}

func wfKnown(t byte) bool {
	switch t {
	case wfOpen, wfData, wfClose, wfWindow, wfPing, wfPong, wfHello, wfWelcome, wfAuthChal, wfAuthResp, wfBye:
		return true
	}
	return false
}

// parseWebFrames splits a carrier message into its frames. The payloads alias msg.
func parseWebFrames(msg []byte) ([]webFrame, error) {
	if len(msg) == 0 {
		return nil, errWebFrame
	}
	var out []webFrame
	for len(msg) > 0 {
		if len(msg) < wfHeaderLen || len(out) == wfMaxBatch {
			return nil, errWebFrame
		}
		t := msg[0]
		id := uint32(msg[1])<<16 | uint32(msg[2])<<8 | uint32(msg[3])
		n := binary.BigEndian.Uint32(msg[4:8])
		if !wfKnown(t) || n > wfMaxPayload || uint64(n) > uint64(len(msg)-wfHeaderLen) {
			return nil, errWebFrame
		}
		end := wfHeaderLen + int(n)
		out = append(out, webFrame{typ: t, stream: id, payload: msg[wfHeaderLen:end:end]})
		msg = msg[end:]
	}
	return out, nil
}

// appendWebFrame appends one frame to b.
func appendWebFrame(b []byte, t byte, stream uint32, payload []byte) []byte {
	b = append(b, t, byte(stream>>16), byte(stream>>8), byte(stream))
	b = binary.BigEndian.AppendUint32(b, uint32(len(payload)))
	return append(b, payload...)
}

// windowDelta reads a WINDOW payload: four bytes, not zero.
func windowDelta(p []byte) (uint32, bool) {
	if len(p) != 4 {
		return 0, false
	}
	d := binary.BigEndian.Uint32(p)
	return d, d != 0
}
