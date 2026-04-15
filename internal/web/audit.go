package web

import (
	"net/http"

	"github.com/lssolutions-ie/lss-management-server/internal/logx"
	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

var auditLg = logx.Component("audit")

// auditServer records a user-originated action, pulling user from request context.
// Silent on error — audit must never block the main flow.
func (s *Server) auditServer(r *http.Request, category, severity, action, entityType, entityID, message string, details map[string]string) {
	u, _ := r.Context().Value(ctxUser).(*models.User)
	s.auditServerFor(r, u, category, severity, action, entityType, entityID, message, details)
}

// auditServerFor records with an explicit user (useful when request context doesn't carry one, e.g. websocket handlers).
func (s *Server) auditServerFor(r *http.Request, u *models.User, category, severity, action, entityType, entityID, message string, details map[string]string) {
	var userID uint64
	var username string
	if u != nil {
		userID = u.ID
		username = u.Username
	}
	ip := ""
	if r != nil {
		ip = r.RemoteAddr
		if f := r.Header.Get("X-Forwarded-For"); f != "" {
			ip = f
		}
	}
	if err := s.DB.InsertServerAuditLog(userID, username, ip, category, severity, action, entityType, entityID, message, details); err != nil {
		auditLg.Error("server insert failed", "err", err.Error())
	}
}
