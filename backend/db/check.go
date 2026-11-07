package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// QuickCheck runs PRAGMA quick_check on an open SQLite database. It reads
// every page but skips the slow index cross-checks of integrity_check.
func QuickCheck(ctx context.Context, conn *sql.DB) error {
	rows, err := conn.QueryContext(ctx, "PRAGMA quick_check")
	if err != nil {
		return err
	}
	defer rows.Close()
	var problems []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return err
		}
		if line != "ok" && len(problems) < 5 {
			problems = append(problems, line)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(problems) > 0 {
		return fmt.Errorf("beschädigt: %s", strings.Join(problems, "; "))
	}
	return nil
}

// QuickCheckFile opens the database at path read-only and checks it. A
// missing file is not an error (the feature behind it is unused).
func QuickCheckFile(ctx context.Context, path string) (bool, error) {
	conn, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return false, err
	}
	defer conn.Close()
	if err := conn.PingContext(ctx); err != nil {
		if strings.Contains(err.Error(), "unable to open") {
			return false, nil
		}
		return false, err
	}
	return true, QuickCheck(ctx, conn)
}
