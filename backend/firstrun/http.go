package firstrun

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"godebplay/backend/auth"
	"godebplay/backend/core"
	"godebplay/plugins/wireguard"
)

// TokenHeader carries the one-time setup token.
const TokenHeader = "X-GoDeb-Setup-Token"

// Mount registers the wizard routes. /api/setup/status and /api/setup/admin
// are public (see auth.protected); admin needs the setup token. The other
// routes need the session the wizard just created with password and 2FA.
// Every route except status refuses once the setup is done.
func Mount(mux *http.ServeMux) {
	MountPublic(mux)
	MountPrivileged(mux)
}

// MountPublic registers the routes the web process serves itself: status
// and creating the first account (database only).
func MountPublic(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/setup/status", handleStatus)
	mux.HandleFunc("POST /api/setup/admin", onlyDuringSetup(handleAdmin))
}

// MountPrivileged registers the steps that change the system (WireGuard,
// ufw, trusted endpoint). With a root agent they run there.
func MountPrivileged(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/setup/info", onlyDuringSetup(handleInfo))
	mux.HandleFunc("POST /api/setup/join", onlyDuringSetup(handleJoin))
	mux.HandleFunc("POST /api/setup/finish", onlyDuringSetup(handleFinish))
	// The overview stays available after the setup (login required).
	mux.HandleFunc("GET /api/setup/summary", handleSummary)
}

func onlyDuringSetup(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !Required() {
			core.WriteError(w, http.StatusGone, "Die Einrichtung ist abgeschlossen")
			return
		}
		fn(w, r)
	}
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	users, _ := auth.HasUsers()
	core.WriteJSON(w, http.StatusOK, map[string]any{"required": Required(), "hasAdmin": users})
}

type adminRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	if !CheckToken(r.Header.Get(TokenHeader)) {
		core.WriteError(w, http.StatusForbidden, "Einrichtungs-Token fehlt oder ist falsch (godeb-play setup-url zeigt ihn)")
		return
	}
	var req adminRequest
	if !core.DecodeJSON(w, r, &req) {
		return
	}
	users, err := auth.HasUsers()
	if err != nil {
		core.WriteError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if users {
		core.WriteError(w, http.StatusConflict, "Es gibt bereits einen Administrator; bitte anmelden")
		return
	}
	if err := CreateAdmin(req.Username, req.Password); err != nil {
		core.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	core.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "username": req.Username})
}

// CreateAdmin creates the first account; 2FA is set up at its first login.
func CreateAdmin(username, password string) error {
	if !auth.ValidUsername(username) {
		return auth.ErrInvalidUsername
	}
	if err := auth.SetPassword(username, password); err != nil {
		return err
	}
	return markStarted()
}

type infoResponse struct {
	Hostname    string             `json:"hostname"`
	PublicIP    string             `json:"publicIp"`
	LAN         []core.LANAddress  `json:"lan"`
	SSHPorts    []int              `json:"sshPorts"`
	Role        wireguard.RoleInfo `json:"role"`
	UFW         string             `json:"ufw"` // missing, inactive, active
	SetupPort   int                `json:"setupPort"`
	Fingerprint string             `json:"fingerprint"`
}

func handleInfo(w http.ResponseWriter, r *http.Request) {
	host, _ := os.Hostname()
	role, _ := wireguard.CurrentRole()
	resp := infoResponse{
		Hostname: host, PublicIP: core.DefaultRoute(r.Context()).Src, LAN: core.LANAddresses(),
		SSHPorts: core.SSHPorts(r.Context()), Role: role, SetupPort: SetupPort(),
	}
	if resp.SSHPorts == nil {
		resp.SSHPorts = []int{}
	}
	switch st := core.RunAdmin(r.Context(), "ufw", "status"); {
	case st.Err != nil:
		resp.UFW = "missing"
	case strings.Contains(st.Stdout, "Status: active"):
		resp.UFW = "active"
	default:
		resp.UFW = "inactive"
	}
	if fp, err := CertFingerprint(); err == nil {
		resp.Fingerprint = fp
	}
	core.WriteJSON(w, http.StatusOK, resp)
}

type joinRequest struct {
	Config string `json:"config"`
}

func handleJoin(w http.ResponseWriter, r *http.Request) {
	var req joinRequest
	if !core.DecodeJSON(w, r, &req) {
		return
	}
	res, err := wireguard.JoinHub(r.Context(), req.Config)
	if err != nil {
		writeErr(w, err)
		return
	}
	resp := map[string]any{"ok": true, "address": res.Address, "hub": res.Hub, "notes": res.Notes}
	if err := wireguard.StartTunnel(r.Context()); err != nil {
		resp["detail"] = err.Error()
	} else {
		resp["handshake"] = wireguard.WaitHandshake(r.Context(), 10*time.Second)
	}
	core.WriteJSON(w, http.StatusOK, resp)
}

// FinishRequest is the last wizard step.
type FinishRequest struct {
	Access     string `json:"access"`
	LANAddress string `json:"lanAddress"`
	LANPort    int    `json:"lanPort"`
	Firewall   bool   `json:"firewall"`
}

// Finish stores the access mode, sets up the firewall and marks the setup done. The public setup listener closes.
func Finish(ctx context.Context, req FinishRequest) ([]string, error) {
	access, err := ResolveAccess(req.Access, req.LANAddress, req.LANPort)
	if err != nil {
		return nil, err
	}
	role, _ := wireguard.CurrentRole()
	if access.Mode == AccessTunnel && role.Role == wireguard.RoleNone {
		return nil, errors.New("Ohne WireGuard ist „nur über den Tunnel“ nicht erreichbar; Heimnetz oder nur lokal wählen")
	}
	var log []string
	plan := FirewallPlan{SSHPorts: core.SSHPorts(ctx), UIPort: 8080, SetupPort: SetupPort(), Enable: req.Firewall}
	if role.Role == wireguard.RoleNone {
		plan.UIPort = 0
	}
	if access.Mode == AccessLAN {
		plan.LANIface, plan.LANAddress, plan.LANPrefix, plan.LANPort = access.Iface, access.Address, access.Prefix, access.Port
	}
	fw, err := ApplyFirewall(ctx, plan)
	log = append(log, fw...)
	if err != nil {
		return log, err
	}
	if err := SaveAccess(access); err != nil {
		return log, err
	}
	return log, MarkDone(string(role.Role), access.Mode)
}

func handleFinish(w http.ResponseWriter, r *http.Request) {
	var req FinishRequest
	if !core.DecodeJSON(w, r, &req) {
		return
	}
	log, err := Finish(r.Context(), req)
	if err != nil {
		core.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "log": log})
		return
	}
	core.WriteJSON(w, http.StatusOK, map[string]any{"ok": true, "log": log, "access": LoadAccess(), "summary": BuildSummary(r.Context())})
}

func writeErr(w http.ResponseWriter, err error) {
	var reqErr *wireguard.RequestError
	if errors.As(err, &reqErr) {
		core.WriteError(w, reqErr.Status, reqErr.Msg)
		return
	}
	core.WriteError(w, http.StatusBadRequest, err.Error())
}

// SetupAddr is where the public setup listener runs (GODEB_SETUP_ADDR).
func SetupAddr() string {
	if v := strings.TrimSpace(os.Getenv("GODEB_SETUP_ADDR")); v != "" {
		return v
	}
	return "0.0.0.0:8443"
}

// SetupPort is the port of SetupAddr.
func SetupPort() int {
	_, port, err := net.SplitHostPort(SetupAddr())
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(port)
	return n
}
