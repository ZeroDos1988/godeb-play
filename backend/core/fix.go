package core

// Fix is the action that resolves a finding: the overview shows a button
// that POSTs Body to Path. Path is always an existing route, so login, the
// agent hand-over and 2FA apply exactly as on the plugin page. Action names
// the button text (i18n key fix.<action>).
type Fix struct {
	Action string `json:"action"`
	Path   string `json:"path"`
	Body   any    `json:"body,omitempty"`
}
