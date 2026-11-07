package wireguard

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"godebplay/backend/core"
)

// Keypair is a WireGuard Curve25519 key pair in base64 form.
type Keypair struct {
	Private string
	Public  string
}

// GenerateKeypair runs `wg genkey` and derives the public key with `wg pubkey`.
func GenerateKeypair(ctx context.Context) (Keypair, error) {
	priv, err := wgKey(ctx, "", "genkey")
	if err != nil {
		return Keypair{}, err
	}
	pub, err := PublicKey(ctx, priv)
	if err != nil {
		return Keypair{}, err
	}
	return Keypair{Private: priv, Public: pub}, nil
}

// PublicKey derives the public key of a private key via `wg pubkey`.
func PublicKey(ctx context.Context, private string) (string, error) {
	if !validKey(private) {
		return "", fmt.Errorf("ungültiger privater Schlüssel")
	}
	return wgKey(ctx, private+"\n", "pubkey")
}

// GeneratePresharedKey runs `wg genpsk`.
func GeneratePresharedKey(ctx context.Context) (string, error) {
	return wgKey(ctx, "", "genpsk")
}

func wgKey(ctx context.Context, stdin, sub string) (string, error) {
	res := core.RunInput(ctx, stdin, "wg", sub)
	if res.Err != nil {
		return "", fmt.Errorf("wg %s: %s", sub, res.Detail())
	}
	key := strings.TrimSpace(res.Stdout)
	if !validKey(key) {
		return "", fmt.Errorf("wg %s lieferte keinen gültigen Schlüssel", sub)
	}
	return key, nil
}

// validKey reports whether s is a base64 encoded 32-byte WireGuard key.
func validKey(s string) bool {
	if len(s) != 44 {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(raw) == 32
}
