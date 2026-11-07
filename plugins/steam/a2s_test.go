package steam

import (
	"bytes"
	"context"
	"net"
	"testing"
)

func infoPacket(players, max byte) []byte {
	p := []byte{0xFF, 0xFF, 0xFF, 0xFF, 'I', 17}
	for _, s := range []string{"GoDeb Enshrouded", "Embervale", "enshrouded", "Enshrouded"} {
		p = append(append(p, s...), 0)
	}
	return append(p, 0x00, 0x00, players, max, 0, 'd', 'w', 0, 1)
}

func TestParseInfo(t *testing.T) {
	info, err := ParseInfo(infoPacket(3, 16))
	if err != nil || info.Name != "GoDeb Enshrouded" || info.Players != 3 || info.MaxPlayers != 16 {
		t.Fatalf("info = %+v, %v", info, err)
	}
	full := infoPacket(3, 16)
	for i := 0; i < len(full)-6; i++ {
		// Every truncation must fail cleanly, never panic.
		if _, err := ParseInfo(full[:i]); err == nil && i < 50 {
			t.Fatalf("truncated at %d accepted", i)
		}
	}
}

func TestQueryInfoWithChallenge(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 1500)
		for i := 0; i < 2; i++ {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if bytes.HasSuffix(buf[:n], []byte{1, 2, 3, 4}) {
				pc.WriteTo(infoPacket(2, 16), addr)
				return
			}
			pc.WriteTo([]byte{0xFF, 0xFF, 0xFF, 0xFF, 'A', 1, 2, 3, 4}, addr)
		}
	}()
	info, err := QueryInfo(context.Background(), pc.LocalAddr().String())
	if err != nil || info.Players != 2 {
		t.Fatalf("info = %+v, %v", info, err)
	}
}
