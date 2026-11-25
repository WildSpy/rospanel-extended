package store

import (
	"database/sql"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// forkOnlyMigrations are fork files upstream AppsGanin/rospanel never had: an upstream
// database has none of them applied, so Open must run them.
var forkOnlyMigrations = map[string]bool{
	"0066_node_rentals.sql":                   true,
	"0067_rent_master_host.sql":               true,
	"0068_reality_default_off.sql":            true,
	"0069_happ_subscriptions.sql":             true,
	"0072_remove_node_rentals.sql":            true,
	"0077_connections_user_last_seen_idx.sql": true,
	"0079_connections_last_seen_idx.sql":      true,
}

// TestUpstreamRenamesPointAtRealFiles keeps the map honest: every target is an embedded
// fork migration, and no upstream name collides with one (which would silently drop a
// fork migration's record).
func TestUpstreamRenamesPointAtRealFiles(t *testing.T) {
	embedded := map[string]bool{}
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	for _, e := range entries {
		embedded[e.Name()] = true
	}
	for _, p := range upstreamRenames {
		if embedded[p[0]] {
			t.Errorf("upstream name %s is also a fork migration file", p[0])
		}
		if !embedded[p[1]] {
			t.Errorf("fork migration %s (for upstream %s) is not embedded", p[1], p[0])
		}
	}
}

// buildUpstreamDB lays down a database the way upstream would have migrated it: the
// same SQL, recorded under upstream's names, without the fork-only migrations.
func buildUpstreamDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(ON)")
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE schema_migrations (
		version TEXT PRIMARY KEY, applied_at INTEGER NOT NULL DEFAULT (unixepoch()))`); err != nil {
		t.Fatalf("schema_migrations: %v", err)
	}
	upstreamName := map[string]string{}
	for _, p := range upstreamRenames {
		upstreamName[p[1]] = p[0]
	}
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	var files []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") && !forkOnlyMigrations[e.Name()] {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	for _, name := range files {
		body, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if _, err := db.Exec(string(body)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
		rec := name
		if up, ok := upstreamName[name]; ok {
			rec = up
		}
		if _, err := db.Exec(`INSERT INTO schema_migrations (version) VALUES (?)`, rec); err != nil {
			t.Fatalf("record %s: %v", rec, err)
		}
	}
	return db
}

// TestOpenUpstreamDatabase reproduces the upstream → fork switch that died with
// "apply 0087_settings_rev.sql: UNIQUE constraint failed: settings_rev.id", and checks
// the data-changing migrations upstream had already applied are not applied again.
func TestOpenUpstreamDatabase(t *testing.T) {
	for _, tc := range []struct {
		name string
		// failedBoot simulates a previous fork boot that re-ran 0070..0086 under the
		// fork's names before dying on 0087.
		failedBoot bool
	}{
		{name: "clean"},
		{name: "after failed fork boot", failedBoot: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "upstream.db")
			db := buildUpstreamDB(t, path)

			// State the upstream panel reached after its migrations: settings edited
			// (settings_rev moved on), an admin who switched the node-traffic alert off,
			// and an AWG slot handed out by the lowest-free allocator, not id+1.
			for _, q := range []string{
				`UPDATE settings SET tg_admin_events = 0 WHERE id = 1`,
				`UPDATE settings_rev SET v = 722 WHERE id = 1`,
				`INSERT INTO users (id, name, uuid, wg_private_key, awg_slot)
				 VALUES (5, 'u5', 'uuid-5', 'key', 2)`,
			} {
				if _, err := db.Exec(q); err != nil {
					t.Fatalf("%s: %v", q, err)
				}
			}
			if tc.failedBoot {
				for _, p := range upstreamRenames {
					if p[1] >= "0087" {
						break
					}
					if _, err := db.Exec(`INSERT INTO schema_migrations (version) VALUES (?)`, p[1]); err != nil {
						t.Fatalf("record %s: %v", p[1], err)
					}
				}
			}
			var rev int
			if err := db.QueryRow(`SELECT v FROM settings_rev WHERE id = 1`).Scan(&rev); err != nil {
				t.Fatalf("read settings_rev: %v", err)
			}
			db.Close()

			st, err := Open(path)
			if err != nil {
				t.Fatalf("Open upstream database: %v", err)
			}
			defer st.Close()

			var got int
			if err := st.db.QueryRow(`SELECT v FROM settings_rev WHERE id = 1`).Scan(&got); err != nil || got < rev {
				t.Errorf("settings_rev = %d (err %v), want >= %d", got, err, rev)
			}
			if err := st.db.QueryRow(`SELECT tg_admin_events FROM settings WHERE id = 1`).Scan(&got); err != nil || got != 0 {
				t.Errorf("tg_admin_events = %d (err %v): 0076_node_traffic_alert_on re-ran", got, err)
			}
			if err := st.db.QueryRow(`SELECT awg_slot FROM users WHERE id = 5`).Scan(&got); err != nil || got != 2 {
				t.Errorf("awg_slot = %d (err %v): 0086_user_awg_slot re-ran", got, err)
			}
			var tables int
			if err := st.db.QueryRow(`SELECT COUNT(1) FROM sqlite_master WHERE type = 'table' AND name = 'happ_subscriptions'`).Scan(&tables); err != nil || tables != 1 {
				t.Errorf("fork-only 0069_happ_subscriptions not applied: %d (err %v)", tables, err)
			}
			for _, p := range upstreamRenames {
				var n int
				_ = st.db.QueryRow(`SELECT COUNT(1) FROM schema_migrations WHERE version = ?`, p[0]).Scan(&n)
				if n != 0 {
					t.Errorf("upstream record %s still present", p[0])
				}
				_ = st.db.QueryRow(`SELECT COUNT(1) FROM schema_migrations WHERE version = ?`, p[1]).Scan(&n)
				if n != 1 {
					t.Errorf("fork record %s missing", p[1])
				}
			}
		})
	}
}
