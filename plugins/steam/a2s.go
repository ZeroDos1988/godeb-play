package steam

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"time"
)

// ServerInfo is the part of an A2S_INFO answer GoDeb shows.
type ServerInfo struct {
	Name       string `json:"name"`
	Map        string `json:"map"`
	Players    int    `json:"players"`
	MaxPlayers int    `json:"maxPlayers"`
	Bots       int    `json:"bots"`
}

var a2sRequest = append([]byte{0xFF, 0xFF, 0xFF, 0xFF, 'T'}, []byte("Source Engine Query\x00")...)

// QueryInfo asks a game server for A2S_INFO over UDP. A server may answer
// with a challenge first; the request is then repeated with it.
func QueryInfo(ctx context.Context, addr string) (ServerInfo, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return ServerInfo{}, err
	}
	defer conn.Close()
	deadline := time.Now().Add(1500 * time.Millisecond)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	req := a2sRequest
	buf := make([]byte, 1400)
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := conn.Write(req); err != nil {
			return ServerInfo{}, err
		}
		n, err := conn.Read(buf)
		if err != nil {
			return ServerInfo{}, err
		}
		pkt := buf[:n]
		if len(pkt) == 9 && bytes.Equal(pkt[:5], []byte{0xFF, 0xFF, 0xFF, 0xFF, 'A'}) {
			req = append(append([]byte(nil), a2sRequest...), pkt[5:9]...)
			continue
		}
		return ParseInfo(pkt)
	}
	return ServerInfo{}, errors.New("A2S: keine Antwort nach Challenge")
}

// ParseInfo decodes a single-packet A2S_INFO response. Every read is bounds
// checked; the packet comes from the network.
func ParseInfo(pkt []byte) (ServerInfo, error) {
	bad := errors.New("A2S: ungültige Antwort")
	if len(pkt) < 6 || !bytes.Equal(pkt[:4], []byte{0xFF, 0xFF, 0xFF, 0xFF}) || pkt[4] != 'I' {
		return ServerInfo{}, bad
	}
	p := pkt[6:] // header, type, protocol version
	str := func() (string, bool) {
		i := bytes.IndexByte(p, 0)
		if i < 0 {
			return "", false
		}
		s := string(p[:i])
		p = p[i+1:]
		if len(s) > 128 {
			s = s[:128]
		}
		return s, true
	}
	var info ServerInfo
	var ok bool
	if info.Name, ok = str(); !ok {
		return ServerInfo{}, bad
	}
	if info.Map, ok = str(); !ok {
		return ServerInfo{}, bad
	}
	if _, ok = str(); !ok { // folder
		return ServerInfo{}, bad
	}
	if _, ok = str(); !ok { // game
		return ServerInfo{}, bad
	}
	if len(p) < 5 {
		return ServerInfo{}, bad
	}
	_ = binary.LittleEndian.Uint16(p[:2]) // app id
	info.Players, info.MaxPlayers, info.Bots = int(p[2]), int(p[3]), int(p[4])
	return info, nil
}
