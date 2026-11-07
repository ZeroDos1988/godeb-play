package mail

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"mime/multipart"
	"net"
	netmail "net/mail"
	"strings"
	"testing"
)

func TestParseConfig(t *testing.T) {
	if _, err := ParseConfig([]byte(`{"host":"smtp.example.org","from":"a@b.c"}`)); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("template accepted: %v", err)
	}
	cfg, err := ParseConfig([]byte(`{"host":"mail.test","from":"GoDeb <a@b.c>","security":"TLS"}`))
	if err != nil || cfg.Port != 465 || cfg.Security != "tls" {
		t.Fatalf("cfg = %#v, %v", cfg, err)
	}
	if _, err := ParseConfig([]byte(`{"host":"mail.test","from":"a@b.c","security":"ssl3"}`)); err == nil {
		t.Fatal("accepted bad security")
	}
}

func TestParseRecipient(t *testing.T) {
	if got, err := ParseRecipient(" Anna <anna@example.org> "); err != nil || got != "anna@example.org" {
		t.Fatalf("got %q, %v", got, err)
	}
	for _, bad := range []string{"", "nope", "a@b.c, d@e.f", "a@b.c\r\nBcc: x@y.z"} {
		if _, err := ParseRecipient(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestSendWithDeliversAttachment(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go fakeSMTP(ln, got)

	cfg := Config{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, From: "GoDeb <godeb@example.org>", Security: "none"}
	msg := Message{
		To:          "anna@example.org",
		Subject:     "WireGuard-Konfiguration für phone",
		Body:        "Anbei die Konfiguration.",
		Attachments: []Attachment{{Name: "phone.conf", ContentType: "text/plain", Data: []byte("[Interface]\nPrivateKey = x\n")}},
	}
	if err := SendWith(context.Background(), cfg, msg); err != nil {
		t.Fatal(err)
	}

	parsed, err := netmail.ReadMessage(strings.NewReader(<-got))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header.Get("To") != "anna@example.org" {
		t.Fatalf("to = %q", parsed.Header.Get("To"))
	}
	_, params, _ := strings.Cut(parsed.Header.Get("Content-Type"), "boundary=")
	reader := multipart.NewReader(parsed.Body, strings.Trim(params, `"`))
	if _, err := reader.NextPart(); err != nil {
		t.Fatal(err)
	}
	part, err := reader.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	if part.FileName() != "phone.conf" {
		t.Fatalf("filename = %q", part.FileName())
	}
	data, _ := io.ReadAll(base64.NewDecoder(base64.StdEncoding, part))
	if string(data) != "[Interface]\nPrivateKey = x\n" {
		t.Fatalf("attachment = %q", data)
	}
}

// fakeSMTP accepts one session without auth and returns the DATA payload.
func fakeSMTP(ln net.Listener, got chan<- string) {
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	reply := func(s string) { _, _ = io.WriteString(conn, s+"\r\n") }
	reply("220 test ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			reply("250 test")
		case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"):
			reply("250 ok")
		case cmd == "DATA":
			reply("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(strings.TrimPrefix(l, "."))
			}
			got <- b.String()
			reply("250 queued")
		case cmd == "QUIT":
			reply("221 bye")
			return
		default:
			reply("502 unsupported")
		}
	}
}
