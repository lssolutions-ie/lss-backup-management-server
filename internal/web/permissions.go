package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

type permissionsPageData struct {
	PageData
	Rules      []*models.PermissionRule
	Users      []*models.User
	UserGroups []*models.UserGroup
	UserTags   []*models.UserTag
	Nodes      []*models.Node
	NodeTags   []*models.Tag
	// Labels for rendering the saved-rules table quickly.
	UserByID      map[uint64]*models.User
	UserGroupByID map[uint64]*models.UserGroup
	UserTagByID   map[uint64]*models.UserTag
	NodeByID      map[uint64]*models.Node
	NodeTagByID   map[uint64]*models.Tag
}

// HandlePermissions renders the GET page.
func (s *Server) HandlePermissions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rules, err := s.DB.ListPermissionRules()
	if err != nil {
		log.Printf("permissions: list: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	users, _ := s.DB.ListUsers()
	userGroups, _ := s.DB.ListUserGroups()
	userTags, _ := s.DB.ListUserTags()
	nodeTags, _ := s.DB.ListTags()

	nodes, _ := s.DB.ListNodesWithStatus(nil)
	nodeList := make([]*models.Node, 0, len(nodes))
	for _, n := range nodes {
		node := n.Node
		nodeList = append(nodeList, &node)
	}

	data := permissionsPageData{
		PageData:      s.newPageData(r),
		Rules:         rules,
		Users:         users,
		UserGroups:    userGroups,
		UserTags:      userTags,
		Nodes:         nodeList,
		NodeTags:      nodeTags,
		UserByID:      map[uint64]*models.User{},
		UserGroupByID: map[uint64]*models.UserGroup{},
		UserTagByID:   map[uint64]*models.UserTag{},
		NodeByID:      map[uint64]*models.Node{},
		NodeTagByID:   map[uint64]*models.Tag{},
	}
	for _, u := range users {
		data.UserByID[u.ID] = u
	}
	for _, g := range userGroups {
		data.UserGroupByID[g.ID] = g
	}
	for _, t := range userTags {
		data.UserTagByID[t.ID] = t
	}
	for _, n := range nodeList {
		data.NodeByID[n.ID] = n
	}
	for _, t := range nodeTags {
		data.NodeTagByID[t.ID] = t
	}

	s.render(w, r, http.StatusOK, "permissions.html", data)
}

type savedRuleJSON struct {
	ID                 uint64 `json:"id"`
	Priority           int    `json:"priority"`
	Enabled            bool   `json:"enabled"`
	Effect             string `json:"effect"`
	Access             string `json:"access"`
	SubjectType        string `json:"subject_type"`
	SubjectID          uint64 `json:"subject_id"`
	TargetType         string `json:"target_type"`
	TargetID           uint64 `json:"target_id"`
	LockedBySuperadmin bool   `json:"locked_by_superadmin"`
}

func ruleToJSON(r *models.PermissionRule) savedRuleJSON {
	return savedRuleJSON{
		ID: r.ID, Priority: r.Priority, Enabled: r.Enabled,
		Effect: string(r.Effect), Access: string(r.Access),
		SubjectType: string(r.SubjectType), SubjectID: r.SubjectID,
		TargetType: string(r.TargetType), TargetID: r.TargetID,
		LockedBySuperadmin: r.LockedBySuperadmin,
	}
}

// HandlePermissionRuleSave creates or updates a single rule.
// If multiple target IDs are submitted via target_ids_csv, one rule per target is created/updated
// (existing id used for the first, new rules for the rest).
// POST /permissions/rule
func (s *Server) HandlePermissionRuleSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	user := r.Context().Value(ctxUser).(*models.User)
	isSuper := user.IsSuperAdmin()

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	existingID, _ := strconv.ParseUint(r.FormValue("rule_id"), 10, 64)
	priority, err := strconv.Atoi(r.FormValue("rule_priority"))
	if err != nil {
		priority = 1000
	}
	subjectID, err1 := strconv.ParseUint(r.FormValue("rule_subject_id"), 10, 64)
	if err1 != nil {
		http.Error(w, "Invalid subject", http.StatusBadRequest)
		return
	}
	effect := models.Effect(r.FormValue("rule_effect"))
	if effect != models.EffectAllow && effect != models.EffectDeny {
		http.Error(w, "Invalid effect", http.StatusBadRequest)
		return
	}
	access := models.AccessLevel(r.FormValue("rule_access"))
	if access != models.AccessView && access != models.AccessManage {
		http.Error(w, "Invalid access", http.StatusBadRequest)
		return
	}
	subjectType := models.SubjectType(r.FormValue("rule_subject_type"))
	if subjectType != models.SubjectUser && subjectType != models.SubjectUserGroup && subjectType != models.SubjectUserTag {
		http.Error(w, "Invalid subject type", http.StatusBadRequest)
		return
	}
	targetType := models.TargetType(r.FormValue("rule_target_type"))
	if targetType != models.TargetNode && targetType != models.TargetNodeTag {
		http.Error(w, "Invalid target type", http.StatusBadRequest)
		return
	}
	var targetIDs []uint64
	for _, v := range strings.Split(r.FormValue("rule_target_ids_csv"), ",") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if id, err := strconv.ParseUint(v, 10, 64); err == nil {
			targetIDs = append(targetIDs, id)
		}
	}
	if len(targetIDs) == 0 {
		http.Error(w, "Select at least one target", http.StatusBadRequest)
		return
	}
	locked := r.FormValue("rule_locked_val") == "1"
	if !isSuper {
		locked = false
		if existingID != 0 {
			if prev, _ := s.findRuleByID(existingID); prev != nil {
				locked = prev.LockedBySuperadmin
				if prev.LockedBySuperadmin {
					http.Error(w, "This rule is locked by superadmin", http.StatusForbidden)
					return
				}
			}
		}
	}

	results := make([]savedRuleJSON, 0, len(targetIDs))
	uid := user.ID
	for idx, tid := range targetIDs {
		if idx == 0 && existingID != 0 {
			prev, err := s.findRuleByID(existingID)
			if err != nil || prev == nil {
				http.Error(w, "Rule not found", http.StatusNotFound)
				return
			}
			if prev.LockedBySuperadmin && !isSuper {
				http.Error(w, "Rule is locked", http.StatusForbidden)
				return
			}
			prev.Priority = priority
			// Preserve enabled unless caller explicitly passed it.
			if v := r.FormValue("rule_enabled"); v != "" {
				prev.Enabled = v == "1"
			}
			prev.Effect = effect
			prev.Access = access
			prev.SubjectType = subjectType
			prev.SubjectID = subjectID
			prev.TargetType = targetType
			prev.TargetID = tid
			prev.LockedBySuperadmin = locked
			if err := s.DB.UpdatePermissionRule(prev); err != nil {
				http.Error(w, "DB error", http.StatusInternalServerError)
				return
			}
			s.auditServer(r, "permission_rule_updated", "info", "update", "permission_rule",
				strconv.FormatUint(prev.ID, 10),
				fmt.Sprintf("Updated permission rule #%d", prev.ID),
				map[string]string{
					"effect":       string(effect),
					"access":       string(access),
					"subject_type": string(subjectType),
					"subject_id":   strconv.FormatUint(subjectID, 10),
					"target_type":  string(targetType),
					"target_id":    strconv.FormatUint(tid, 10),
					"priority":     strconv.Itoa(priority),
				})
			results = append(results, ruleToJSON(prev))
		} else {
			nr := &models.PermissionRule{
				Priority:           priority,
				Enabled:            true,
				Effect:             effect,
				Access:             access,
				SubjectType:        subjectType,
				SubjectID:          subjectID,
				TargetType:         targetType,
				TargetID:           tid,
				LockedBySuperadmin: locked,
				CreatedBy:          &uid,
			}
			id, err := s.DB.CreatePermissionRule(nr)
			if err != nil {
				http.Error(w, "DB error", http.StatusInternalServerError)
				return
			}
			nr.ID = id
			s.auditServer(r, "permission_rule_created", "info", "create", "permission_rule",
				strconv.FormatUint(id, 10),
				fmt.Sprintf("Created permission rule #%d", id),
				map[string]string{
					"effect":       string(effect),
					"access":       string(access),
					"subject_type": string(subjectType),
					"subject_id":   strconv.FormatUint(subjectID, 10),
					"target_type":  string(targetType),
					"target_id":    strconv.FormatUint(tid, 10),
					"priority":     strconv.Itoa(priority),
				})
			results = append(results, ruleToJSON(nr))
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"rules": results})
}

// HandlePermissionRuleToggle toggles the enabled flag.
// POST /permissions/rule/{id}/toggle
func (s *Server) HandlePermissionRuleToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	user := r.Context().Value(ctxUser).(*models.User)
	rest := strings.TrimPrefix(r.URL.Path, "/permissions/rule/")
	parts := strings.SplitN(rest, "/", 2)
	id, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	prev, err := s.findRuleByID(id)
	if err != nil || prev == nil {
		http.NotFound(w, r)
		return
	}
	if prev.LockedBySuperadmin && !user.IsSuperAdmin() {
		http.Error(w, "Rule locked", http.StatusForbidden)
		return
	}
	newEnabled := !prev.Enabled
	if err := s.DB.SetPermissionRuleEnabled(id, newEnabled); err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	sev := "info"
	if !newEnabled {
		sev = "warn"
	}
	s.auditServer(r, "permission_rule_toggled", sev, "toggle", "permission_rule",
		strconv.FormatUint(id, 10),
		fmt.Sprintf("Toggled permission rule #%d enabled=%t", id, newEnabled),
		map[string]string{"enabled": fmt.Sprintf("%t", newEnabled)})
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"id":%d,"enabled":%t}`, id, newEnabled)
}

// HandlePermissionRuleDelete
// POST /permissions/rule/{id}/delete
func (s *Server) HandlePermissionRuleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	user := r.Context().Value(ctxUser).(*models.User)
	rest := strings.TrimPrefix(r.URL.Path, "/permissions/rule/")
	parts := strings.SplitN(rest, "/", 2)
	id, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	prev, err := s.findRuleByID(id)
	if err != nil || prev == nil {
		http.NotFound(w, r)
		return
	}
	if prev.LockedBySuperadmin && !user.IsSuperAdmin() {
		http.Error(w, "Rule locked", http.StatusForbidden)
		return
	}
	if err := s.DB.DeletePermissionRule(id); err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	s.auditServer(r, "permission_rule_deleted", "warn", "delete", "permission_rule",
		strconv.FormatUint(id, 10),
		fmt.Sprintf("Deleted permission rule #%d", id),
		map[string]string{
			"effect":       string(prev.Effect),
			"access":       string(prev.Access),
			"subject_type": string(prev.SubjectType),
			"subject_id":   strconv.FormatUint(prev.SubjectID, 10),
			"target_type":  string(prev.TargetType),
			"target_id":    strconv.FormatUint(prev.TargetID, 10),
		})
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"id":%d,"deleted":true}`, id)
}

func (s *Server) findRuleByID(id uint64) (*models.PermissionRule, error) {
	all, err := s.DB.ListPermissionRules()
	if err != nil {
		return nil, err
	}
	for _, r := range all {
		if r.ID == id {
			return r, nil
		}
	}
	return nil, nil
}
