// Package mail sends messages through the SMTP server configured in
// /etc/godeb-play/smtp.json.
package mail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net"
	netmail "net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"godebplay/backend/core"
)

// ConfigPath holds the SMTP credentials. It is created as a template on first use.
const ConfigPath = "/etc/godeb-play/smtp.json"

const templateHost = "smtp.example.org"

// ErrNotConfigured means smtp.json is missing or still the template.
var ErrNotConfigured = errors.New("SMTP ist nicht konfiguriert: " + ConfigPath + " ausfüllen")

// Config mirrors /etc/godeb-play/smtp.json. Security is "starttls" (default),
// "tls" for implicit TLS on port 465, or "none" for a local relay.
type Config struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Pass     string `json:"pass"`
	From     string `json:"from"`
	Security string `json:"security"`
}

// Attachment is one file attached to a message.
type Attachment struct {
	Name        string
	ContentType string
	Data        []byte
}

// Message is a plain-text mail with optional attachments.
type Message struct {
	To          string
	Subject     string
	Body        string
	Attachments []Attachment
}

var template = Config{
	Host:     templateHost,
	Port:     587,
	User:     "godeb@example.org",
	Pass:     "",
	From:     "GoDeb <godeb@example.org>",
	Security: "starttls",
}

// LoadConfig reads smtp.json. A missing file is replaced by a 0600 template
// and reported as ErrNotConfigured.
func LoadConfig() (Config, error) {
	data, err := core.ReadAdminFile(ConfigPath)
	if errors.Is(err, fs.ErrNotExist) {
		raw, _ := json.MarshalIndent(template, "", "  ")
		if werr := core.WriteAdminFile(ConfigPath, append(raw, '\n'), 0o600); werr != nil {
			return Config{}, fmt.Errorf("%w (Vorlage nicht angelegt: %v)", ErrNotConfigured, werr)
		}
		return Config{}, ErrNotConfigured
	}
	if err != nil {
		return Config{}, err
	}
	return ParseConfig(data)
}

// ParseConfig validates smtp.json content.
func ParseConfig(data []byte) (Config, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("%s ist kein gültiges JSON: %w", ConfigPath, err)
	}
	cfg.Host = strings.TrimSpace(cfg.Host)
	cfg.Security = strings.ToLower(strings.TrimSpace(cfg.Security))
	if cfg.Host == "" || cfg.Host == templateHost {
		return Config{}, ErrNotConfigured
	}
	if cfg.Security == "" {
		cfg.Security = "starttls"
	}
	if cfg.Security != "starttls" && cfg.Security != "tls" && cfg.Security != "none" {
		return Config{}, fmt.Errorf("security muss starttls, tls oder none sein")
	}
	if cfg.Port == 0 {
		cfg.Port = 587
		if cfg.Security == "tls" {
			cfg.Port = 465
		}
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return Config{}, fmt.Errorf("port %d ist ungültig", cfg.Port)
	}
	if _, err := netmail.ParseAddress(cfg.From); err != nil {
		return Config{}, fmt.Errorf("from ist keine gültige Adresse: %w", err)
	}
	return cfg, nil
}

// ParseRecipient accepts exactly one address and returns it in bare form.
func ParseRecipient(raw string) (string, error) {
	if strings.ContainsAny(raw, "\r\n,;") {
		return "", errors.New("genau eine Empfängeradresse angeben")
	}
	addr, err := netmail.ParseAddress(strings.TrimSpace(raw))
	if err != nil {
		return "", errors.New("Empfängeradresse ist ungültig")
	}
	return addr.Address, nil
}

// Send loads smtp.json and delivers msg.
func Send(ctx context.Context, msg Message) error {
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	return SendWith(ctx, cfg, msg)
}

// SendWith delivers msg using cfg.
func SendWith(ctx context.Context, cfg Config, msg Message) error {
	to, err := ParseRecipient(msg.To)
	if err != nil {
		return err
	}
	from, err := netmail.ParseAddress(cfg.From)
	if err != nil {
		return fmt.Errorf("from ist ungültig: %w", err)
	}
	body, err := Build(from, to, msg, time.Now())
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	tlsConfig := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}

	dialer := &net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	if cfg.Security == "tls" {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: tlsConfig}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("SMTP-Verbindung zu %s: %w", addr, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("SMTP-Begrüßung: %w", err)
	}
	defer client.Close()

	if cfg.Security == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("SMTP-Server bietet kein STARTTLS an")
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("STARTTLS: %w", err)
		}
	}
	if cfg.User != "" {
		if err := client.Auth(smtp.PlainAuth("", cfg.User, cfg.Pass, cfg.Host)); err != nil {
			return fmt.Errorf("SMTP-Anmeldung: %w", err)
		}
	}
	if err := client.Mail(from.Address); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		w.Close()
		return fmt.Errorf("DATA: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	return client.Quit()
}

// Build renders msg as a multipart/mixed RFC 5322 message with CRLF line endings.
func Build(from *netmail.Address, to string, msg Message, now time.Time) ([]byte, error) {
	boundary, err := randomToken()
	if err != nil {
		return nil, err
	}
	domain := "localhost"
	if at := strings.LastIndexByte(from.Address, '@'); at >= 0 {
		domain = from.Address[at+1:]
	}
	id, err := randomToken()
	if err != nil {
		return nil, err
	}

	var b bytes.Buffer
	header := func(k, v string) {
		v = strings.NewReplacer("\r", " ", "\n", " ").Replace(v)
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	header("From", from.String())
	header("To", to)
	header("Subject", mime.QEncoding.Encode("utf-8", msg.Subject))
	header("Date", now.Format(time.RFC1123Z))
	header("Message-ID", "<"+id+"@"+domain+">")
	header("MIME-Version", "1.0")
	header("Content-Type", `multipart/mixed; boundary="`+boundary+`"`)
	b.WriteString("\r\n")

	fmt.Fprintf(&b, "--%s\r\n", boundary)
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	writeBase64(&b, []byte(msg.Body))

	for _, a := range msg.Attachments {
		ctype := a.ContentType
		if ctype == "" {
			ctype = "application/octet-stream"
		}
		name := mime.QEncoding.Encode("utf-8", a.Name)
		fmt.Fprintf(&b, "--%s\r\n", boundary)
		fmt.Fprintf(&b, "Content-Type: %s; name=\"%s\"\r\n", ctype, name)
		fmt.Fprintf(&b, "Content-Disposition: attachment; filename=\"%s\"\r\n", name)
		b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
		writeBase64(&b, a.Data)
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes(), nil
}

func writeBase64(b *bytes.Buffer, data []byte) {
	enc := base64.StdEncoding.EncodeToString(data)
	for len(enc) > 76 {
		b.WriteString(enc[:76])
		b.WriteString("\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc)
	b.WriteString("\r\n")
}

func randomToken() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
