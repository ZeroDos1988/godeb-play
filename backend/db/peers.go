package db

import "time"

// PeerRecord is one WireGuard address reservation. The live peer still comes
// from wg0.conf; this row only remembers which address GoDeb handed out.
type PeerRecord struct {
	Name      string
	PublicKey string
	Address   string
	CreatedAt string
}

// PeerAddresses returns every reserved client address.
func PeerAddresses() ([]string, error) {
	conn, err := AgentOpen()
	if err != nil {
		return nil, err
	}
	rows, err := conn.Query(`SELECT address FROM wireguard_peers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var address string
		if err := rows.Scan(&address); err != nil {
			return nil, err
		}
		out = append(out, address)
	}
	return out, rows.Err()
}

// HasPeer reports whether name already has a reservation.
func HasPeer(name string) (bool, error) {
	conn, err := AgentOpen()
	if err != nil {
		return false, err
	}
	var found int
	err = conn.QueryRow(`SELECT COUNT(*) FROM wireguard_peers WHERE name = ?`, name).Scan(&found)
	return found > 0, err
}

// SavePeer inserts or refreshes a reservation.
func SavePeer(name, publicKey, address string) error {
	conn, err := AgentOpen()
	if err != nil {
		return err
	}
	_, err = conn.Exec(
		`INSERT INTO wireguard_peers (name, public_key, address, created_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(name) DO UPDATE SET public_key = excluded.public_key, address = excluded.address`,
		name, publicKey, address, time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

// DeletePeer removes a reservation. A missing name is not an error.
func DeletePeer(name string) error {
	conn, err := AgentOpen()
	if err != nil {
		return err
	}
	_, err = conn.Exec(`DELETE FROM wireguard_peers WHERE name = ?`, name)
	return err
}
