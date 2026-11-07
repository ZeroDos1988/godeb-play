package wireguard

import (
	"errors"
	"net/http"

	"godebplay/backend/core"
	"godebplay/backend/mail"
)

type emailRequest struct {
	To string `json:"to"`
}

// handleSendEmail mails the client configuration, plus a QR code when
// qrencode is available.
func handleSendEmail(w http.ResponseWriter, r *http.Request) {
	var req emailRequest
	if !core.DecodeJSON(w, r, &req) {
		return
	}
	to, err := mail.ParseRecipient(req.To)
	if err != nil {
		core.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	id, data, ok := readClient(w, r)
	if !ok {
		return
	}

	attachments := []mail.Attachment{{Name: id + ".conf", ContentType: "text/plain", Data: data}}
	if png, err := RenderQR(r.Context(), data); err == nil {
		attachments = append(attachments, mail.Attachment{Name: id + ".png", ContentType: "image/png", Data: png})
	}
	msg := mail.Message{
		To:      to,
		Subject: "WireGuard-Konfiguration " + id,
		Body: "Im Anhang befindet sich die WireGuard-Konfiguration " + id + ".conf.\r\n\r\n" +
			"Desktop: Datei in der WireGuard-App über \"Tunnel aus Datei importieren\" laden.\r\n" +
			"Mobil: Den angehängten QR-Code in der WireGuard-App scannen.\r\n\r\n" +
			"Die Datei enthält einen privaten Schlüssel. Bitte nicht weiterleiten und nach dem Import löschen.\r\n",
		Attachments: attachments,
	}
	if err := mail.Send(r.Context(), msg); err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, mail.ErrNotConfigured) {
			status = http.StatusConflict
		}
		core.WriteError(w, status, err.Error())
		return
	}
	core.WriteJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"to":          to,
		"attachments": len(attachments),
	})
}
