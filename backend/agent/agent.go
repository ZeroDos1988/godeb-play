// Package agent splits GoDeb into two processes. The web process (user
// godeb) owns the listeners, login, sessions and the static UI. The agent
// (root) owns everything that changes the system: plugin routes, the plugin
// manager and the privileged setup steps. Both talk HTTP over a Unix socket
// that only root and the web user can connect to.
//
// Without GODEB_AGENT_SOCKET the web process mounts everything itself, as
// before the split; development and the tests run that way.
package agent

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/user"
	"path"
	"strconv"
	"strings"
	"syscall"

	"godebplay/backend/state"
)

// DefaultSocket is where godeb-play-agent.service listens (RuntimeDirectory).
const DefaultSocket = "/run/godeb-play-agent/agent.sock"

// UserHeader carries the logged-in user from the web process to the agent.
// The web process removes it from every incoming request before it sets it.
const UserHeader = "X-GoDeb-User"

// internalHeaders are set by the web process only, never by the browser.
// X-GoDeb-Password is stripped too: the web process already checked it and
// the agent must not see account passwords.
var internalHeaders = []string{UserHeader, SessionHeader, ClientIPHeader, "X-GoDeb-Password"}

// SocketPath is the agent socket the web process forwards to, from
// GODEB_AGENT_SOCKET. Empty means no agent: everything runs in-process.
func SocketPath() string {
	return strings.TrimSpace(os.Getenv("GODEB_AGENT_SOCKET"))
}

// WebUser is the account of the unprivileged web process (GODEB_WEB_USER,
// default godeb). The agent lets it connect and hands it the socket group.
func WebUser() string {
	return state.WebUser()
}

// privilegedSetup are the wizard steps that change the system. Status and
// admin creation stay in the web process.
var privilegedSetup = map[string]bool{
	"/api/setup/info":     true,
	"/api/setup/hub":      true,
	"/api/setup/client":   true,
	"/api/setup/join":     true,
	"/api/setup/services": true,
	"/api/setup/domains":  true,
	"/api/setup/finish":   true,
	"/api/setup/summary":  true,
}

// Routed reports whether a request path is served by the agent.
func Routed(p string) bool {
	p = path.Clean("/" + p)
	switch {
	case strings.HasPrefix(p, "/api/plugins/"):
		return true
	case p == "/api/plugin-manager", strings.HasPrefix(p, "/api/plugin-manager/"):
		return true
	}
	return privilegedSetup[p]
}

// PrivilegedSetupRoutes lists the setup paths the web process forwards.
func PrivilegedSetupRoutes() []string {
	out := make([]string, 0, len(privilegedSetup))
	for p := range privilegedSetup {
		out = append(out, p)
	}
	return out
}

// User returns the logged-in user the web process forwarded, "" for public
// routes such as the APK download.
func User(r *http.Request) string {
	return r.Header.Get(UserHeader)
}

// ClientIP returns the browser address the web process forwarded.
func ClientIP(r *http.Request) string {
	return r.Header.Get(ClientIPHeader)
}

// Guard is the outermost handler of the agent: it serves only the routes
// that belong to the agent, so a bug in the web process cannot reach
// anything else that might be mounted.
func Guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !Routed(r.URL.Path) && !strings.HasPrefix(path.Clean(r.URL.Path), InternalPrefix) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Peers decides which local users may talk to the agent.
type Peers struct {
	uids map[uint32]bool
}

// AllowedPeers admits root, the agent's own user (development without
// root) and the web user if that account exists.
func AllowedPeers(webUser string) Peers {
	p := Peers{uids: map[uint32]bool{0: true, uint32(os.Getuid()): true}}
	if u, err := user.Lookup(webUser); err == nil {
		if uid, err := strconv.ParseUint(u.Uid, 10, 32); err == nil {
			p.uids[uint32(uid)] = true
		}
	}
	return p
}

// Allows reports whether uid may connect.
func (p Peers) Allows(uid uint32) bool {
	return p.uids[uid]
}

// Listen opens the agent socket with mode 0660. As root it hands the group
// to the web user, so the file permission and the peer check both apply.
func Listen(sock string, peers Peers, webUser string) (net.Listener, error) {
	if st, err := os.Lstat(sock); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s existiert und ist kein Socket", sock)
		}
		if err := os.Remove(sock); err != nil {
			return nil, err
		}
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(sock, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	if os.Geteuid() == 0 {
		if u, err := user.Lookup(webUser); err == nil {
			if gid, err := strconv.Atoi(u.Gid); err == nil {
				if err := os.Chown(sock, 0, gid); err != nil {
					ln.Close()
					return nil, err
				}
			}
		}
	}
	return &peerListener{Listener: ln, peers: peers}, nil
}

// peerListener drops connections whose peer uid is not allowed, checked by
// the kernel through SO_PEERCRED.
type peerListener struct {
	net.Listener
	peers Peers
}

func (l *peerListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uid, err := peerUID(conn)
		if err == nil && l.peers.Allows(uid) {
			return conn, nil
		}
		if err != nil {
			slog.Warn("Peer-Prüfung am Agent-Socket fehlgeschlagen", "fehler", err)
		} else {
			slog.Warn("Verbindung zum Agenten abgelehnt", "uid", uid)
		}
		conn.Close()
	}
}

func peerUID(conn net.Conn) (uint32, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, errors.New("keine Unix-Verbindung")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	return cred.Uid, nil
}
