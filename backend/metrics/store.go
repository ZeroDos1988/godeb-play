package metrics

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/glebarez/go-sqlite" // pure-Go SQLite driver "sqlite", already used through GORM
)

// DefaultPath is the history database of the agent (StateDirectory of
// godeb-play-agent.service, root only). It holds numbers and events, nothing
// the agent acts on.
const DefaultPath = "/var/lib/godeb-play-agent/metrics.db"

// Path returns GODEB_METRICS_DB, a file in GODEB_STATE_DIR for development,
// or DefaultPath.
func Path() string {
	if p := strings.TrimSpace(os.Getenv("GODEB_METRICS_DB")); p != "" {
		return p
	}
	if d := strings.TrimSpace(os.Getenv("GODEB_STATE_DIR")); d != "" {
		return filepath.Join(d, "metrics.db")
	}
	return DefaultPath
}

// Tiers of the history: raw samples, 5-minute and hourly aggregates.
type tier struct {
	id     int
	step   int64 // seconds per point
	retain time.Duration
}

var tiers = []tier{
	{0, int64(Interval / time.Second), 26 * time.Hour},
	{1, 300, 31 * 24 * time.Hour},
	{2, 3600, 400 * 24 * time.Hour},
}

const eventRetention = 400 * 24 * time.Hour

// Store is the SQLite history.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// OpenStore opens or creates the history database at path (mode 0600).
func OpenStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("Verzeichnis der Messwerte: %w", err)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS points (tier INTEGER NOT NULL, series TEXT NOT NULL, ts INTEGER NOT NULL, avg REAL NOT NULL, max REAL NOT NULL, PRIMARY KEY (tier, series, ts)) WITHOUT ROWID`,
		`CREATE INDEX IF NOT EXISTS points_ts ON points (tier, ts)`,
		`CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, source TEXT NOT NULL, level TEXT NOT NULL, text TEXT NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS events_ts ON events (ts)`,
		`CREATE TABLE IF NOT EXISTS rollups (tier INTEGER PRIMARY KEY, done INTEGER NOT NULL)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			db.Close()
			return nil, fmt.Errorf("Messwert-Datenbank %s: %w", path, err)
		}
	}
	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, now: time.Now}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Write stores raw values at ts (unix seconds).
func (s *Store) Write(ctx context.Context, ts int64, values map[string]float64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO points (tier, series, ts, avg, max) VALUES (0, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for name, v := range values {
		if _, err := stmt.ExecContext(ctx, name, ts, v, v); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// AddEvent stores an event.
func (s *Store) AddEvent(ctx context.Context, e Event) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO events (ts, source, level, text) VALUES (?, ?, ?, ?)`, e.Time, e.Source, string(e.Level), e.Text)
	return err
}

// Rollup aggregates finished buckets of each tier into the next one and
// drops what is older than a tier keeps.
func (s *Store) Rollup(ctx context.Context) error {
	now := s.now().Unix()
	for i := 1; i < len(tiers); i++ {
		t, src := tiers[i], tiers[i-1]
		var done int64
		err := s.db.QueryRowContext(ctx, `SELECT done FROM rollups WHERE tier = ?`, t.id).Scan(&done)
		if err == sql.ErrNoRows {
			// Start with the oldest data of the source tier.
			var oldest sql.NullInt64
			if err := s.db.QueryRowContext(ctx, `SELECT MIN(ts) FROM points WHERE tier = ?`, src.id).Scan(&oldest); err != nil {
				return err
			}
			if !oldest.Valid {
				continue
			}
			done = oldest.Int64 / t.step * t.step
		} else if err != nil {
			return err
		}
		end := now / t.step * t.step
		if end <= done {
			continue
		}
		if _, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO points (tier, series, ts, avg, max)
			SELECT ?, series, (ts / ?) * ?, AVG(avg), MAX(max) FROM points
			WHERE tier = ? AND ts >= ? AND ts < ? GROUP BY series, ts / ?`,
			t.id, t.step, t.step, src.id, done, end, t.step); err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO rollups (tier, done) VALUES (?, ?)`, t.id, end); err != nil {
			return err
		}
	}
	for _, t := range tiers {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM points WHERE tier = ? AND ts < ?`, t.id, now-int64(t.retain/time.Second)); err != nil {
			return err
		}
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE ts < ?`, now-int64(eventRetention/time.Second))
	return err
}

// Point is one value of a queried series: time, average and maximum.
type Point [3]float64

// Range is a queried time window.
type Range struct {
	From   int64              `json:"from"`
	To     int64              `json:"to"`
	Step   int64              `json:"step"`
	Series map[string][]Point `json:"series"`
}

// maxPoints keeps charts light; the step grows with the span.
const maxPoints = 480

// Query returns the series matching names (exact, or a prefix ending in
// "*") between from and to, with at most maxPoints points each.
func (s *Store) Query(ctx context.Context, names []string, from, to int64) (Range, error) {
	span := to - from
	t := tiers[len(tiers)-1]
	for _, c := range tiers {
		// Use the finest tier that still covers the start of the window.
		if s.now().Unix()-from <= int64(c.retain/time.Second) {
			t = c
			break
		}
	}
	step := t.step
	if span/step > maxPoints {
		step = (span/maxPoints + t.step - 1) / t.step * t.step
	}
	out := Range{From: from, To: to, Step: step, Series: map[string][]Point{}}
	var where []string
	args := []any{step, step, t.id, from, to}
	for _, n := range names {
		if p, ok := strings.CutSuffix(n, "*"); ok {
			where = append(where, `series >= ? AND series < ?`)
			args = append(args, p, p+"\xff")
		} else {
			where = append(where, `series = ?`)
			args = append(args, n)
		}
	}
	if len(where) == 0 {
		return out, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT series, (ts / ?) * ? AS b, AVG(avg), MAX(max) FROM points
		WHERE tier = ? AND ts >= ? AND ts <= ? AND ((`+strings.Join(where, ") OR (")+`))
		GROUP BY series, b ORDER BY series, b`, args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var b int64
		var avg, max float64
		if err := rows.Scan(&name, &b, &avg, &max); err != nil {
			return out, err
		}
		out.Series[name] = append(out.Series[name], Point{float64(b), avg, max})
	}
	return out, rows.Err()
}

// Events returns events between from and to, oldest first, at most limit.
func (s *Store) Events(ctx context.Context, from, to int64, limit int) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ts, source, level, text FROM (
		SELECT ts, source, level, text, id FROM events WHERE ts >= ? AND ts <= ? ORDER BY ts DESC, id DESC LIMIT ?
	) ORDER BY ts, id`, from, to, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var level string
		if err := rows.Scan(&e.Time, &e.Source, &level, &e.Text); err != nil {
			return nil, err
		}
		e.Level = Status(level)
		out = append(out, e)
	}
	return out, rows.Err()
}

// HourlyHistory returns the hourly averages of one series since from, for
// the baseline.
func (s *Store) HourlyHistory(ctx context.Context, series string, from int64) ([]Point, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ts, avg, max FROM points WHERE tier = 2 AND series = ? AND ts >= ? ORDER BY ts`, series, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Point
	for rows.Next() {
		var ts int64
		var avg, max float64
		if err := rows.Scan(&ts, &avg, &max); err != nil {
			return nil, err
		}
		out = append(out, Point{float64(ts), avg, max})
	}
	return out, rows.Err()
}
