package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Server struct {
		ListenAddr string
	}
	Database struct {
		DSN string
	}
	Security struct {
		SecretKeyFile string
	}
	Session struct {
		CookieName  string
		MaxAgeHours int
	}
}

// Load reads a TOML config file from the given path.
// Handles the simple key = "value" / key = integer format used by this project.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	cfg := &Config{}
	// sensible defaults
	cfg.Server.ListenAddr = "127.0.0.1:8080"
	cfg.Session.CookieName = "lss_session"
	cfg.Session.MaxAgeHours = 24

	var section string
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		// strip surrounding quotes from string values
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = val[1 : len(val)-1]
		}

		switch section + "." + key {
		case "server.listen_addr":
			cfg.Server.ListenAddr = val
		case "database.dsn":
			cfg.Database.DSN = val
		case "security.secret_key_file":
			cfg.Security.SecretKeyFile = val
		case "session.cookie_name":
			cfg.Session.CookieName = val
		case "session.max_age_hours":
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("invalid max_age_hours %q: %w", val, err)
			}
			cfg.Session.MaxAgeHours = n
		}
	}

	if cfg.Database.DSN == "" {
		return nil, fmt.Errorf("config missing [database] dsn")
	}
	if cfg.Security.SecretKeyFile == "" {
		return nil, fmt.Errorf("config missing [security] secret_key_file")
	}

	return cfg, nil
}
