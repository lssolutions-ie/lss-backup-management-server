package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	"github.com/lssolutions-ie/lss-management-server/internal/logx"
)

var lg = logx.Component("db")

// DB wraps *sql.DB and exposes all query helpers.
type DB struct {
	db *sql.DB
}

// Open connects to MySQL and returns a *DB.
func Open(dsn string) (*DB, error) {
	sqlDB, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}
	return &DB{db: sqlDB}, nil
}

// Close closes the underlying connection pool.
func (d *DB) Close() error {
	return d.db.Close()
}

// RunMigrations reads *.sql files from dir in lexicographic order, executes any
// not yet recorded in the schema_migrations table, and records them.
func (d *DB) RunMigrations(dir string) error {
	_, err := d.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		name       VARCHAR(255) NOT NULL PRIMARY KEY,
		applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read migrations dir %q: %w", dir, err)
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		// Down-migrations are documentation/operator-rollback only — the runner
		// never auto-applies them. See migrations/README.md.
		if strings.HasSuffix(name, ".down.sql") {
			continue
		}
		files = append(files, name)
	}
	sort.Strings(files)

	for _, name := range files {
		var count int
		if err := d.db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE name = ?", name).Scan(&count); err != nil {
			return fmt.Errorf("check migration %s: %w", name, err)
		}
		if count > 0 {
			continue
		}

		content, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}

		for _, stmt := range splitSQL(string(content)) {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			if _, err := d.db.Exec(stmt); err != nil {
				return fmt.Errorf("apply migration %s: %w\nSQL: %s", name, err, stmt)
			}
		}

		if _, err := d.db.Exec("INSERT INTO schema_migrations (name) VALUES (?)", name); err != nil {
			return fmt.Errorf("record migration %s: %w", name, err)
		}
		lg.Info("applied migration", "name", name)
	}
	return nil
}

// splitSQL splits a SQL file into individual statements on semicolons.
func splitSQL(sql string) []string {
	raw := strings.Split(sql, ";")
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
