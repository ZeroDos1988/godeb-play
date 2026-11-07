package main

import (
	"context"
	"net/http"
	"time"

	"godebplay/backend/agent"
	"godebplay/backend/core"
	"godebplay/backend/db"
	"godebplay/backend/doctor"
	"godebplay/backend/metrics"
)

// doctorEnv is the host Env used by the CLI and the agent internal route.
func doctorEnv() doctor.Env {
	env := doctor.Default(version)
	// The agent and the CLI (root) only check root's own files; the web
	// database belongs to the user godeb and is checked by the web process.
	env.Databases = []doctor.DBFile{
		{Name: "Agent-Datenbank", Path: db.AgentPath()},
		{Name: "Messwerte", Path: metrics.Path()},
	}
	env.CheckDB = db.QuickCheckFile
	return env
}

// webDatabaseFindings checks the web process's own database.
func webDatabaseFindings(ctx context.Context) []doctor.Finding {
	if db.Path() == db.AgentPath() {
		return nil // development: one file, already checked
	}
	env := doctor.Env{
		Databases: []doctor.DBFile{{Name: "Web-Datenbank", Path: db.Path()}},
		CheckDB:   db.QuickCheckFile,
	}
	return doctor.CheckOnly(ctx, env, doctor.CheckDatabases)
}

// runDoctorReport runs the read-only checks and returns the JSON report.
func runDoctorReport(ctx context.Context) doctor.Report {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	return doctor.NewReport(doctor.Check(ctx, doctorEnv()), time.Now())
}

// mountDoctorAPI exposes GET /api/doctor for the overview. With an agent the
// web process only forwards; without one it runs the checks itself (dev).
func mountDoctorAPI(mux *http.ServeMux, client *agent.Client) {
	mux.HandleFunc("GET /api/doctor", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if client != nil {
			var report doctor.Report
			if err := client.Call(r.Context(), http.MethodGet, "/internal/doctor", nil, &report); err != nil {
				core.WriteError(w, http.StatusBadGateway, err.Error())
				return
			}
			report.Add(webDatabaseFindings(r.Context()))
			core.WriteJSON(w, http.StatusOK, report)
			return
		}
		core.WriteJSON(w, http.StatusOK, runDoctorReport(r.Context()))
	})
}
