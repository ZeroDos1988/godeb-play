package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"godebplay/backend/firstrun"
	"godebplay/backend/remoteaccess"
)

// tlsListeners runs the self-signed HTTPS listeners GoDeb has besides
// loopback and wg0: the public setup listener while the first-run setup is
// open, later the LAN listener if the admin chose access from the home
// network, and the temporary remote access on the public address.
type tlsListeners struct {
	mu      sync.Mutex
	handler http.Handler
	servers map[string]*http.Server
	wake    chan struct{}
}

func newTLSListeners(h http.Handler) *tlsListeners {
	t := &tlsListeners{handler: h, servers: map[string]*http.Server{}, wake: make(chan struct{}, 1)}
	firstrun.OnChange(func() {
		select {
		case t.wake <- struct{}{}:
		default:
		}
	})
	return t
}

// desired lists the HTTPS addresses to serve: the setup listener while the
// setup is open, otherwise the LAN listener and, while it lasts, the
// temporary remote access on the public address.
func (t *tlsListeners) desired(now time.Time) map[string]string {
	want := map[string]string{}
	if firstrun.Required() {
		want[firstrun.SetupAddr()] = "setup"
		return want
	}
	if addr := firstrun.LoadAccess().Addr(); addr != "" {
		want[addr] = "lan"
	}
	if addr := remoteaccess.Load().Addr(now); addr != "" && want[addr] == "" {
		want[addr] = "remote"
	}
	return want
}

func (t *tlsListeners) sync() {
	want := t.desired(time.Now())
	t.mu.Lock()
	defer t.mu.Unlock()
	for addr, srv := range t.servers {
		if want[addr] != "" {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = srv.Shutdown(ctx)
		cancel()
		delete(t.servers, addr)
		slog.Info("HTTPS geschlossen", "adresse", addr)
	}
	for addr, kind := range want {
		if t.servers[addr] == nil {
			t.open(addr, kind)
		}
	}
}

func (t *tlsListeners) open(addr, kind string) {
	cert, fp, err := firstrun.EnsureCert()
	if err != nil {
		slog.Error("Zertifikat nicht verfügbar", "fehler", err)
		return
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Warn("HTTPS noch nicht möglich", "adresse", addr, "fehler", err)
		return
	}
	srv := &http.Server{
		Handler:           t.handler,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	t.servers[addr] = srv
	go func() {
		if err := srv.Serve(tls.NewListener(ln, srv.TLSConfig)); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTPS-Server beendet", "adresse", addr, "fehler", err)
		}
	}()
	switch kind {
	case "setup":
		slog.Warn("Ersteinrichtung offen, Link mit Token: sudo godeb-play setup-url", "url", "https://"+addr, "zertifikat_sha256", fp)
	case "remote":
		slog.Warn("Fernzugang offen", "url", "https://"+addr, "bis", remoteaccess.Load().Until.Local().Format(time.DateTime), "zertifikat_sha256", fp)
	default:
		slog.Info("GoDeb Play lauscht im Heimnetz", "url", "https://"+addr)
	}
}

// run keeps the listener in line with the setup state and access mode. The
// poll catches changes made by the CLI, which runs in another process.
func (t *tlsListeners) run(ctx context.Context) {
	for {
		t.sync()
		select {
		case <-ctx.Done():
			return
		case <-t.wake:
		case <-time.After(3 * time.Second):
		}
	}
}
