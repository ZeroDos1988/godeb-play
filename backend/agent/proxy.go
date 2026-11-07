package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"path"
	"time"

	"godebplay/backend/core"
)

// SessionHeader identifies the browser session towards the agent as a hash
// of the session cookie, never the cookie itself.
const SessionHeader = "X-GoDeb-Session"

// SessionID hashes a session token for SessionHeader.
func SessionID(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("godeb-play-agent-session\n" + token))
	return hex.EncodeToString(sum[:16])
}

// ClientIPHeader passes the browser's address to the agent for its audit
// log. Informational only: the agent never decides anything by it.
const ClientIPHeader = "X-GoDeb-Client-IP"

// Identity is what the web process tells the agent about a request.
type Identity struct {
	User    string
	Session string // session token, hashed before it is sent
}

type identityKey struct{}

// NewProxy forwards requests to the agent socket. identify runs after the
// web process has checked the session; internal headers from the browser
// are always dropped first, and so is the cookie, which the agent does not
// need. verdict sees the agent's response headers with the raw session id
// (step-up window opened, session to end) before the browser does.
func NewProxy(sock string, identify func(*http.Request) Identity, verdict func(session string, h http.Header)) http.Handler {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
		MaxIdleConns:          16,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: 0, // package installs answer late
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = "godeb-play-agent"
			pr.Out.Host = "godeb-play-agent"
			for _, h := range internalHeaders {
				pr.Out.Header.Del(h)
			}
			pr.Out.Header.Del("Cookie")
			id := identify(pr.In)
			pr.Out = pr.Out.WithContext(context.WithValue(pr.Out.Context(), identityKey{}, id))
			if id.User != "" {
				pr.Out.Header.Set(UserHeader, id.User)
			}
			if s := SessionID(id.Session); s != "" {
				pr.Out.Header.Set(SessionHeader, s)
			}
			if ip := core.ClientIP(pr.In); ip != "" {
				pr.Out.Header.Set(ClientIPHeader, ip)
			}
		},
		Transport:     transport,
		FlushInterval: -1,
		ModifyResponse: func(resp *http.Response) error {
			id, _ := resp.Request.Context().Value(identityKey{}).(Identity)
			if verdict != nil {
				verdict(id.Session, resp.Header)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Error("Agent nicht erreichbar", "methode", r.Method, "pfad", r.URL.Path, "fehler", err)
			core.WriteError(w, http.StatusBadGateway, "GoDeb-Agent nicht erreichbar (systemctl status godeb-play-agent)")
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only clean agent routes leave this process; never /internal/.
		if r.URL.Path != path.Clean(r.URL.Path) || !Routed(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		rp.ServeHTTP(w, r)
	})
}

// InternalPrefix holds routes only the web process calls directly, never
// forwarded from a browser (the proxy only forwards Routed paths).
const InternalPrefix = "/internal/"

// Client calls the agent's internal routes from the web process.
type Client struct {
	http *http.Client
}

// NewClient returns a client for the agent socket.
func NewClient(sock string) *Client {
	return &Client{http: &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
			MaxIdleConns:    4,
			IdleConnTimeout: 60 * time.Second,
		},
	}}
}

// Call sends body (nil for GET) as JSON and decodes the answer into out.
func (c *Client) Call(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://godeb-play-agent"+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			return errors.New(e.Error)
		}
		return fmt.Errorf("Agent %s: HTTP %d", path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}
