package web

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/lssolutions-ie/lss-management-server/internal/crypto"
	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

type nodeDetailPageData struct {
	PageData
	Node    *models.Node
	Jobs    []models.JobSnapshot
	Reports []*models.NodeReport
	Total   int
	Page    int
	Pages   int
}

type nodeFormPageData struct {
	PageData
	Groups []*models.ClientGroup
	Node   *models.Node // nil when creating
	Error  string
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

	jobs, err := s.DB.ListJobSnapshots(node.ID)
	if err != nil {
		log.Printf("node detail: list jobs: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	const perPage = 50
	page := 1
	if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && p > 1 {
		page = p
	}
	offset := (page - 1) * perPage

	total, err := s.DB.CountNodeReports(node.ID)
	if err != nil {
		log.Printf("node detail: count reports: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	reports, err := s.DB.ListNodeReports(node.ID, perPage, offset)
	if err != nil {
		log.Printf("node detail: list reports: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	pages := (total + perPage - 1) / perPage
	if pages < 1 {
		pages = 1
	}

	s.render(w, r, http.StatusOK, "node_detail.html", nodeDetailPageData{
		PageData: s.newPageData(r),
		Node:     node,
		Jobs:     jobs,
		Reports:  reports,
		Total:    total,
		Page:     page,
		Pages:    pages,
	})
}

// HandleNodeNew shows the register-node form (GET) and creates a node (POST).
func (s *Server) HandleNodeNew(w http.ResponseWriter, r *http.Request) {
	if !s.EnforceWrite(w, r) {
		return
	}
	groups, err := s.DB.ListClientGroups()
	if err != nil {
		log.Printf("node new: list groups: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if r.Method == http.MethodGet {
		s.render(w, r, http.StatusOK, "node_new.html", nodeFormPageData{
			PageData: s.newPageData(r),
			Groups:   groups,
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
			Error:    "All fields are required.",
		})
		return
	}

	groupID, err := strconv.ParseUint(groupIDStr, 10, 64)
	if err != nil {
		s.render(w, r, http.StatusUnprocessableEntity, "node_new.html", nodeFormPageData{
			PageData: s.newPageData(r),
			Groups:   groups,
			Error:    "Invalid client group.",
		})
		return
	}

	psk, err := crypto.GeneratePSK()
	if err != nil {
		log.Printf("node new: generate psk: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	encrypted, err := crypto.EncryptPSK(psk, s.AppKey)
	if err != nil {
		log.Printf("node new: encrypt psk: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	nodeID, err := s.DB.CreateNode(uid, name, groupID, encrypted)
	if err != nil {
		log.Printf("node new: create: %v", err)
		s.render(w, r, http.StatusUnprocessableEntity, "node_new.html", nodeFormPageData{
			PageData: s.newPageData(r),
			Groups:   groups,
			Error:    "Could not create node (UID may already be registered).",
		})
		return
	}

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

	groups, err := s.DB.ListClientGroups()
	if err != nil {
		log.Printf("node edit: list groups: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
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
		log.Printf("node edit: update: %v", err)
		s.render(w, r, http.StatusInternalServerError, "node_edit.html", nodeFormPageData{
			PageData: s.newPageData(r),
			Groups:   groups,
			Node:     node,
			Error:    "Could not update node.",
		})
		return
	}

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
	if !ok {
		return
	}

	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	if err := s.DB.DeleteNode(node.ID); err != nil {
		log.Printf("node delete: %v", err)
		setFlash(w, "Could not delete node.")
		http.Redirect(w, r, fmt.Sprintf("/nodes/%d", node.ID), http.StatusSeeOther)
		return
	}

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

	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	psk, err := crypto.GeneratePSK()
	if err != nil {
		log.Printf("regen psk: generate: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	encrypted, err := crypto.EncryptPSK(psk, s.AppKey)
	if err != nil {
		log.Printf("regen psk: encrypt: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if err := s.DB.UpdateNodePSK(node.ID, encrypted); err != nil {
		log.Printf("regen psk: update: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	s.setPSKFlash(w, psk)
	http.Redirect(w, r, fmt.Sprintf("/nodes/%d/psk", node.ID), http.StatusSeeOther)
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
		log.Printf("nodeFromPath: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil, false
	}
	if node == nil {
		http.NotFound(w, r)
		return nil, false
	}
	return node, true
}
