package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/lssolutions-ie/lss-management-server/internal/crypto"
	"github.com/lssolutions-ie/lss-management-server/internal/logx"
	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

type nodeDetailPageData struct {
	PageData
	Node         *models.Node
	Jobs         []models.JobSnapshot
	Reports      []*models.NodeReport
	AllTags      []*models.Tag
	NodeAccess     models.AccessLevel
	Silences       map[string]*models.JobSilence // keyed by jobID
	JobTagsByID    map[string][]models.JobTag    // keyed by jobID
	AllJobTags     []*models.JobTag
	AnomalyCounts  map[string]int                // unack'd anomaly count keyed by jobID
	Total        int
	Page         int
	Pages        int
	PerPage      int
	FilterType   string
	FilterStatus string
	FilterFrom   string
	FilterTo     string
}

type nodeFormPageData struct {
	PageData
	Groups  []*models.ClientGroup
	AllTags []*models.Tag
	Node    *models.Node // nil when creating
	Error   string
}

type nodePSKPageData struct {
	PageData
	Node *models.Node
	PSK  string
}

// HandleNodeDetail shows node info, jobs, and check-in history.
func (s *Server) HandleNodeDetail(w http.ResponseWriter, r *http.Request) {
	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if !ok {
		return
	}
	if !s.EnforceNodeView(w, r, node.ID) {
		return
	}

	jobs, err := s.DB.ListJobSnapshots(node.ID)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	// Load tags for this node and all available tags.
	nodeTags, _ := s.DB.GetNodeTags(node.ID)
	node.Tags = nodeTags
	allTags, _ := s.DB.ListTags()

	q := r.URL.Query()

	perPage := 25
	if pp, err := strconv.Atoi(q.Get("per_page")); err == nil && pp > 0 && pp <= 200 {
		perPage = pp
	}
	page := 1
	if p, err := strconv.Atoi(q.Get("page")); err == nil && p > 1 {
		page = p
	}

	filterType := q.Get("type")
	filterStatus := q.Get("status")
	filterFrom := q.Get("from")
	filterTo := q.Get("to")

	filter := models.ReportFilter{
		NodeID: node.ID,
		Type:   filterType,
		Status: filterStatus,
		From:   filterFrom,
		To:     filterTo,
		Limit:  perPage,
		Offset: (page - 1) * perPage,
	}

	total, err := s.DB.CountNodeReportsFiltered(filter)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	reports, err := s.DB.ListNodeReportsFiltered(filter)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	pages := (total + perPage - 1) / perPage
	if pages < 1 {
		pages = 1
	}

	user := r.Context().Value(ctxUser).(*models.User)
	access := s.EffectiveNodeAccess(user, node.ID)

	// Per-job silences + job tag links
	silenceMap := make(map[string]*models.JobSilence)
	jobTagMap := make(map[string][]models.JobTag)
	for _, j := range jobs {
		if sil, _ := s.DB.GetJobSilence(node.ID, j.JobID); sil != nil && sil.IsActive() {
			silenceMap[j.JobID] = sil
		}
		if jt, _ := s.DB.GetJobTags(node.ID, j.JobID); len(jt) > 0 {
			jobTagMap[j.JobID] = jt
		}
	}
	allJobTags, _ := s.DB.ListJobTags()
	anomalyCounts, _ := s.DB.CountUnackedAnomaliesByJob(node.ID)

	s.render(w, r, http.StatusOK, "node_detail.html", nodeDetailPageData{
		PageData:     s.newPageData(r),
		Node:         node,
		Jobs:         jobs,
		Reports:      reports,
		AllTags:      allTags,
		NodeAccess:    access,
		Silences:      silenceMap,
		JobTagsByID:   jobTagMap,
		AllJobTags:    allJobTags,
		AnomalyCounts: anomalyCounts,
		Total:        total,
		Page:         page,
		Pages:        pages,
		PerPage:      perPage,
		FilterType:   filterType,
		FilterStatus: filterStatus,
		FilterFrom:   filterFrom,
		FilterTo:     filterTo,
	})
}

// HandleNodeNew shows the register-node form (GET) and creates a node (POST).
func (s *Server) HandleNodeNew(w http.ResponseWriter, r *http.Request) {
	if !s.EnforceWrite(w, r) {
		return
	}
	groups, err := s.DB.ListClientGroups()
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	allTags, _ := s.DB.ListTags()

	if r.Method == http.MethodGet {
		s.render(w, r, http.StatusOK, "node_new.html", nodeFormPageData{
			PageData: s.newPageData(r),
			Groups:   groups,
			AllTags:  allTags,
		})
		return
	}

	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	uid := strings.TrimSpace(r.FormValue("uid"))
	groupIDStr := r.FormValue("client_group_id")

	if name == "" || uid == "" || groupIDStr == "" {
		s.render(w, r, http.StatusUnprocessableEntity, "node_new.html", nodeFormPageData{
			PageData: s.newPageData(r),
			Groups:   groups,
			AllTags:  allTags,
			Error:    "All fields are required.",
		})
		return
	}

	groupID, err := strconv.ParseUint(groupIDStr, 10, 64)
	if err != nil {
		s.render(w, r, http.StatusUnprocessableEntity, "node_new.html", nodeFormPageData{
			PageData: s.newPageData(r),
			Groups:   groups,
			AllTags:  allTags,
			Error:    "Invalid client group.",
		})
		return
	}

	psk, err := crypto.GeneratePSK()
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	encrypted, err := crypto.EncryptPSK(psk, s.AppKey)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	nodeID, err := s.DB.CreateNode(uid, name, groupID, encrypted)
	if err != nil {
		logx.FromContext(r.Context()).Error("create node failed", "err", err.Error())
		s.render(w, r, http.StatusUnprocessableEntity, "node_new.html", nodeFormPageData{
			PageData: s.newPageData(r),
			Groups:   groups,
			AllTags:  allTags,
			Error:    "Could not create node (UID may already be registered).",
		})
		return
	}

	// Assign existing tags.
	var tagIDs []uint64
	for _, v := range r.Form["tag_ids"] {
		if id, err := strconv.ParseUint(v, 10, 64); err == nil {
			tagIDs = append(tagIDs, id)
		}
	}

	// Create new tag if provided.
	newTagName := strings.TrimSpace(r.FormValue("new_tag_name"))
	if newTagName != "" {
		newTagColor := r.FormValue("new_tag_color")
		if newTagColor == "" {
			newTagColor = "#206bc4"
		}
		newTagTextColor := r.FormValue("new_tag_text_color")
		if newTagTextColor == "" {
			newTagTextColor = "#ffffff"
		}
		if newID, err := s.DB.CreateTagWithTextColor(newTagName, newTagColor, newTagTextColor); err == nil {
			tagIDs = append(tagIDs, newID)
		}
	}

	if len(tagIDs) > 0 {
		_ = s.DB.SetNodeTags(nodeID, tagIDs)
	}

	s.auditServer(r, "node_created", "info", "create", "node",
		strconv.FormatUint(nodeID, 10),
		"Registered node "+name,
		map[string]string{"name": name, "uid": uid, "client_group_id": strconv.FormatUint(groupID, 10)})

	s.setPSKFlash(w, psk)
	http.Redirect(w, r, fmt.Sprintf("/nodes/%d/psk", nodeID), http.StatusSeeOther)
}

// HandleNodePSK shows the one-time PSK display page.
func (s *Server) HandleNodePSK(w http.ResponseWriter, r *http.Request) {
	if !s.EnforceWrite(w, r) {
		return
	}
	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if !ok {
		return
	}
	if !s.EnforceNodeManage(w, r, node.ID) {
		return
	}

	psk := s.getPSKFlash(w, r)
	if psk == "" {
		setFlash(w, "The PSK has already been displayed or has expired. Use Regenerate PSK if needed.")
		http.Redirect(w, r, fmt.Sprintf("/nodes/%d", node.ID), http.StatusSeeOther)
		return
	}

	s.render(w, r, http.StatusOK, "node_psk.html", nodePSKPageData{
		PageData: s.newPageData(r),
		Node:     node,
		PSK:      psk,
	})
}

// HandleNodeEdit shows the edit form (GET) and updates a node (POST).
func (s *Server) HandleNodeEdit(w http.ResponseWriter, r *http.Request) {
	if !s.EnforceWrite(w, r) {
		return
	}
	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if !ok {
		return
	}
	if !s.EnforceNodeManage(w, r, node.ID) {
		return
	}

	groups, err := s.DB.ListClientGroups()
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	if r.Method == http.MethodGet {
		s.render(w, r, http.StatusOK, "node_edit.html", nodeFormPageData{
			PageData: s.newPageData(r),
			Groups:   groups,
			Node:     node,
		})
		return
	}

	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	groupIDStr := r.FormValue("client_group_id")

	if name == "" || groupIDStr == "" {
		s.render(w, r, http.StatusUnprocessableEntity, "node_edit.html", nodeFormPageData{
			PageData: s.newPageData(r),
			Groups:   groups,
			Node:     node,
			Error:    "All fields are required.",
		})
		return
	}

	groupID, err := strconv.ParseUint(groupIDStr, 10, 64)
	if err != nil {
		s.render(w, r, http.StatusUnprocessableEntity, "node_edit.html", nodeFormPageData{
			PageData: s.newPageData(r),
			Groups:   groups,
			Node:     node,
			Error:    "Invalid client group.",
		})
		return
	}

	if err := s.DB.UpdateNode(node.ID, name, groupID); err != nil {
		logx.FromContext(r.Context()).Error("update node failed", "err", err.Error())
		s.render(w, r, http.StatusInternalServerError, "node_edit.html", nodeFormPageData{
			PageData: s.newPageData(r),
			Groups:   groups,
			Node:     node,
			Error:    "Could not update node.",
		})
		return
	}

	s.auditServer(r, "node_updated", "info", "update", "node",
		strconv.FormatUint(node.ID, 10),
		"Updated node "+name,
		map[string]string{"name": name, "client_group_id": strconv.FormatUint(groupID, 10)})

	setFlash(w, "Node updated.")
	http.Redirect(w, r, fmt.Sprintf("/nodes/%d", node.ID), http.StatusSeeOther)
}

// HandleNodeDelete deletes a node (POST only).
func (s *Server) HandleNodeDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !s.EnforceWrite(w, r) {
		return
	}

	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if ok && !s.EnforceNodeManage(w, r, node.ID) {
		return
	}
	if !ok {
		return
	}

	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	if err := s.DB.DeleteNode(node.ID); err != nil {
		logx.FromContext(r.Context()).Error("delete node failed", "err", err.Error())
		setFlash(w, "Could not delete node.")
		http.Redirect(w, r, fmt.Sprintf("/nodes/%d", node.ID), http.StatusSeeOther)
		return
	}

	s.auditServer(r, "node_deleted", "critical", "delete", "node",
		strconv.FormatUint(node.ID, 10),
		"Deleted node "+node.Name,
		map[string]string{"name": node.Name, "uid": node.UID})

	setFlash(w, "Node deleted.")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// HandleNodeRegeneratePSK generates a new PSK for a node (POST only).
func (s *Server) HandleNodeRegeneratePSK(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !s.EnforceWrite(w, r) {
		return
	}

	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if !ok {
		return
	}
	if !s.EnforceNodeManage(w, r, node.ID) {
		return
	}

	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	psk, err := crypto.GeneratePSK()
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	encrypted, err := crypto.EncryptPSK(psk, s.AppKey)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	if err := s.DB.UpdateNodePSK(node.ID, encrypted); err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}

	s.auditServer(r, "node_psk_regenerated", "warn", "regenerate", "node",
		strconv.FormatUint(node.ID, 10),
		"Regenerated PSK for node "+node.Name,
		map[string]string{"name": node.Name, "uid": node.UID})

	s.setPSKFlash(w, psk)
	http.Redirect(w, r, fmt.Sprintf("/nodes/%d/psk", node.ID), http.StatusSeeOther)
}

// HandleNodeTags updates tags for a node.
func (s *Server) HandleNodeTags(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !s.EnforceWrite(w, r) {
		return
	}

	node, ok := s.nodeFromPath(w, r, "/nodes/")
	if !ok {
		return
	}
	if !s.EnforceNodeManage(w, r, node.ID) {
		return
	}

	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	// Collect selected tag IDs from form.
	var tagIDs []uint64
	for _, v := range r.Form["tag_ids"] {
		if id, err := strconv.ParseUint(v, 10, 64); err == nil {
			tagIDs = append(tagIDs, id)
		}
	}

	if err := s.DB.SetNodeTags(node.ID, tagIDs); err != nil {
		logx.FromContext(r.Context()).Error("set node tags failed", "err", err.Error())
	}

	s.auditServer(r, "node_tags_updated", "info", "update", "node",
		strconv.FormatUint(node.ID, 10),
		"Updated tags for node "+node.Name,
		map[string]string{"name": node.Name, "tag_count": strconv.Itoa(len(tagIDs))})

	setFlash(w, "Tags updated.")
	http.Redirect(w, r, fmt.Sprintf("/nodes/%d", node.ID), http.StatusSeeOther)
}

// nodeFromPath extracts a node ID from the URL path and returns the node.
// The segment after prefix is expected to be either just the ID, or ID/suffix.
func (s *Server) nodeFromPath(w http.ResponseWriter, r *http.Request, prefix string) (*models.Node, bool) {
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	// rest may be "123" or "123/edit" or "123/psk" etc.
	parts := strings.SplitN(rest, "/", 2)
	idStr := parts[0]

	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return nil, false
	}

	node, err := s.DB.GetNodeByID(id)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return nil, false
	}
	if node == nil {
		http.NotFound(w, r)
		return nil, false
	}
	return node, true
}
