package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// ifaceName matches Linux interface names such as wg0.
var ifaceName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,14}$`)

// listenSpec is one entry of GODEB_ADDR. Either Addr is a host:port, or
// Iface names an interface whose first IPv4 address is used with Port.
type listenSpec struct {
	Addr  string
	Iface string
	Port  string
}

func (s listenSpec) String() string {
	if s.Iface != "" {
		return s.Iface + ":" + s.Port
	}
	return s.Addr
}

// parseListen reads a comma-separated GODEB_ADDR such as
// "127.0.0.1:8080,wg0:8080". An interface name stands for its IPv4 address,
// so the UI is reachable through the tunnel without binding to the LAN.
func parseListen(raw string) ([]listenSpec, error) {
	var out []listenSpec
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		host, port, err := net.SplitHostPort(part)
		if err != nil {
			return nil, fmt.Errorf("GODEB_ADDR %q: %w", part, err)
		}
		if host != "" && net.ParseIP(host) == nil && host != "localhost" {
			if !ifaceName.MatchString(host) {
				return nil, fmt.Errorf("GODEB_ADDR %q: weder IP noch Interface", part)
			}
			out = append(out, listenSpec{Iface: host, Port: port})
			continue
		}
		out = append(out, listenSpec{Addr: part})
	}
	if len(out) == 0 {
		return nil, errors.New("GODEB_ADDR ist leer")
	}
	return out, nil
}

// resolve returns the concrete host:port for the spec.
func (s listenSpec) resolve() (string, error) {
	if s.Iface == "" {
		return s.Addr, nil
	}
	ifc, err := net.InterfaceByName(s.Iface)
	if err != nil {
		return "", err
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			return net.JoinHostPort(ipnet.IP.String(), s.Port), nil
		}
	}
	return "", fmt.Errorf("%s hat keine IPv4-Adresse", s.Iface)
}

// serveAll serves srv on every spec. The first spec must bind at startup.
// Later ones (for example wg0 before the tunnel is up) are retried until
// they succeed or ctx ends.
func serveAll(ctx context.Context, srv *http.Server, specs []listenSpec) error {
	first, err := listen(specs[0])
	if err != nil {
		return err
	}
	go serve(srv, first)
	for _, spec := range specs[1:] {
		go func(spec listenSpec) {
			delay := 2 * time.Second
			for {
				ln, err := listen(spec)
				if err == nil {
					serve(srv, ln)
					return
				}
				slog.Warn("Lauschen noch nicht möglich, neuer Versuch", "adresse", spec, "fehler", err, "in", delay)
				select {
				case <-ctx.Done():
					return
				case <-time.After(delay):
				}
				if delay < time.Minute {
					delay *= 2
				}
			}
		}(spec)
	}
	return nil
}

func listen(spec listenSpec) (net.Listener, error) {
	addr, err := spec.resolve()
	if err != nil {
		return nil, err
	}
	return net.Listen("tcp", addr)
}

func serve(srv *http.Server, ln net.Listener) {
	slog.Info("GoDeb lauscht", "adresse", ln.Addr().String())
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("HTTP-Server beendet", "adresse", ln.Addr().String(), "fehler", err)
	}
}
