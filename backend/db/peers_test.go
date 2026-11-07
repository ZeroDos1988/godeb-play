package db

import (
	"path/filepath"
	"testing"
)

func TestPeerReservationRoundTrip(t *testing.T) {
	t.Setenv("GODEB_DB", filepath.Join(t.TempDir(), "godeb.db"))
	if err := SavePeer("laptop", "pubkey", "10.8.0.2"); err != nil {
		t.Fatal(err)
	}
	taken, err := HasPeer("laptop")
	if err != nil || !taken {
		t.Fatalf("taken=%v err=%v", taken, err)
	}
	addrs, err := PeerAddresses()
	if err != nil || len(addrs) != 1 || addrs[0] != "10.8.0.2" {
		t.Fatalf("addrs=%v err=%v", addrs, err)
	}
	if err := SavePeer("laptop", "pubkey-2", "10.8.0.4"); err != nil {
		t.Fatal(err)
	}
	addrs, err = PeerAddresses()
	if err != nil || len(addrs) != 1 || addrs[0] != "10.8.0.4" {
		t.Fatalf("updated=%v err=%v", addrs, err)
	}
	if err := DeletePeer("laptop"); err != nil {
		t.Fatal(err)
	}
	taken, err = HasPeer("laptop")
	if err != nil || taken {
		t.Fatalf("after delete taken=%v err=%v", taken, err)
	}
}
