// Package classify assigns a coarse category to raw backup error messages.
// Rules are pattern-based and live here (server side). The CLI sends raw
// `last_error` strings; we decide what they mean.
package classify

import (
	"regexp"
	"strings"
)

// Categories. Keep these stable; the UI groups by them.
const (
	CatNetwork    = "network"
	CatAuth       = "auth"
	CatDiskFull   = "disk_full"
	CatPermission = "permission"
	CatRepoCorrupt = "repo_corrupt"
	CatTimeout    = "timeout"
	CatConfig     = "config"
	CatCancelled  = "cancelled"
	CatOther      = "other"
)

type rule struct {
	category string
	patterns []*regexp.Regexp
}

// Rules list — order matters for ambiguous strings (first match wins).
var rules = []rule{
	{CatCancelled, compile([]string{
		`(?i)\bcancell?ed\b`,
		`(?i)\bkilled\b`,
		`(?i)\binterrupted\b`,
		`(?i)signal: killed`,
	})},
	{CatTimeout, compile([]string{
		`(?i)timed?\s*out`,
		`(?i)deadline exceeded`,
		`(?i)context canceled`,
	})},
	{CatDiskFull, compile([]string{
		`(?i)no space left on device`,
		`(?i)disk full`,
		`(?i)ENOSPC`,
		`(?i)quota exceeded`,
	})},
	{CatPermission, compile([]string{
		`(?i)permission denied`,
		`(?i)EACCES`,
		`(?i)operation not permitted`,
	})},
	{CatAuth, compile([]string{
		`(?i)auth(entication|orization)? failed`,
		`(?i)unauthori[sz]ed`,
		`(?i)invalid credentials`,
		`(?i)bad password`,
		`(?i)403 forbidden`,
		`(?i)401 unauthori[sz]ed`,
		`(?i)SignatureDoesNotMatch`,
		`(?i)AccessDenied`,
		`(?i)wrong password`,
	})},
	{CatRepoCorrupt, compile([]string{
		`(?i)repository.*corrupt`,
		`(?i)pack.*corrupt`,
		`(?i)Fatal:.*pack`,
		`(?i)invalid data: ciphertext verification failed`,
		`(?i)error loading index`,
		`(?i)unable to open config file`,
	})},
	{CatNetwork, compile([]string{
		`(?i)connection refused`,
		`(?i)connection reset`,
		`(?i)no route to host`,
		`(?i)name resolution`,
		`(?i)dial (tcp|udp)`,
		`(?i)DNS`,
		`(?i)network is unreachable`,
		`(?i)TLS handshake`,
		`(?i)i/o timeout`,
		`(?i)EOF`,
	})},
	{CatConfig, compile([]string{
		`(?i)invalid.*config`,
		`(?i)unknown option`,
		`(?i)missing.*required`,
		`(?i)no such repository`,
		`(?i)no such file or directory`,
	})},
}

func compile(patterns []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, regexp.MustCompile(p))
	}
	return out
}

// Classify returns the best category guess for a raw error message.
// Empty input returns "" (no classification).
func Classify(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	for _, r := range rules {
		for _, pat := range r.patterns {
			if pat.MatchString(s) {
				return r.category
			}
		}
	}
	return CatOther
}
