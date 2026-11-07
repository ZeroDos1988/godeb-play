package db

// migrations are applied in order. Each entry is one version and may contain
// several statements. Version 1 creates the metadata tables.
var migrations = [][]string{
	{
		`CREATE TABLE users (
			username TEXT PRIMARY KEY,
			password_hash TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE user_settings (
			username TEXT PRIMARY KEY REFERENCES users(username),
			theme_mode TEXT NOT NULL DEFAULT 'system',
			color_primary TEXT NOT NULL DEFAULT '#a80030',
			color_bg TEXT NOT NULL DEFAULT '#f3efe6',
			color_accent TEXT NOT NULL DEFAULT '#246b45',
			color_text TEXT NOT NULL DEFAULT '#1c1915',
			updated_at TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE wireguard_peers (
			name TEXT PRIMARY KEY,
			public_key TEXT NOT NULL DEFAULT '',
			address TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT ''
		)`,
	},
	{
		`ALTER TABLE users ADD COLUMN totp_secret TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE users ADD COLUMN totp_confirmed INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN backup_codes TEXT NOT NULL DEFAULT '[]'`,
		`ALTER TABLE users ADD COLUMN last_step INTEGER NOT NULL DEFAULT 0`,
	},
	{
		`CREATE TABLE oidc_providers (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL DEFAULT '',
			client_id TEXT NOT NULL DEFAULT '',
			client_secret TEXT NOT NULL DEFAULT '',
			enabled INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE oidc_admin_emails (
			provider TEXT NOT NULL,
			email TEXT NOT NULL,
			username TEXT NOT NULL DEFAULT '',
			PRIMARY KEY (provider, email)
		)`,
	},
	{
		`ALTER TABLE user_settings ADD COLUMN language TEXT NOT NULL DEFAULT ''`,
	},
	{
		// Server-side logins. id is the SHA-256 of the cookie's token ID.
		// Timestamps are Unix seconds.
		`CREATE TABLE sessions (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			stage TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			last_seen INTEGER NOT NULL,
			elevated_until INTEGER NOT NULL DEFAULT 0,
			failures INTEGER NOT NULL DEFAULT 0,
			ip TEXT NOT NULL DEFAULT '',
			user_agent TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX sessions_username ON sessions(username)`,
	},
}
