package web

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

type tagNodeInfo struct {
	ID   uint64
	Name string
}

type tagsPageData struct {
	PageData
	Tags        []*models.Tag
	NodesByTag  map[uint64][]tagNodeInfo
}

type tagEditPageData struct {
	PageData
	Tag   *models.Tag
	Error string
}

// HandleTags lists all tags.
func (s *Server) HandleTags(w http.ResponseWriter, r *http.Request) {
	tags, err := s.DB.ListTags()
	if err != nil {
		log.Printf("tags: list: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Load node assignments for each tag.
	tagIDs := make([]uint64, len(tags))
	for i, t := range tags {
		tagIDs[i] = t.ID
	}
	usage, _ := s.DB.GetNodesUsingTags(tagIDs)
	nodesByTag := make(map[uint64][]tagNodeInfo, len(usage))
	for tagID, entries := range usage {
		for _, e := range entries {
			nodesByTag[tagID] = append(nodesByTag[tagID], tagNodeInfo{ID: e.NodeID, Name: e.NodeName})
		}
	}

	s.render(w, r, http.StatusOK, "tags.html", tagsPageData{
		PageData:   s.newPageData(r),
		Tags:       tags,
		NodesByTag: nodesByTag,
	})
}

// HandleTagEdit shows and processes the tag edit form.
func (s *Server) HandleTagEdit(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/tags/")
	idStr = strings.TrimSuffix(idStr, "/edit")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	tag, err := s.DB.GetTagByID(id)
	if err != nil || tag == nil {
		http.NotFound(w, r)
		return
	}

	if r.Method == http.MethodGet {
		s.render(w, r, http.StatusOK, "tag_edit.html", tagEditPageData{
			PageData: s.newPageData(r),
			Tag:      tag,
		})
		return
	}

	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	color := r.FormValue("color")
	if name == "" {
		s.render(w, r, http.StatusUnprocessableEntity, "tag_edit.html", tagEditPageData{
			PageData: s.newPageData(r),
			Tag:      tag,
			Error:    "Tag name is required.",
		})
		return
	}

	textColor := r.FormValue("text_color")
	if textColor == "" {
		textColor = "#ffffff"
	}

	if err := s.DB.UpdateTag(id, name, color, textColor); err != nil {
		log.Printf("tag edit: update: %v", err)
	}

	setFlash(w, "Tag updated.")
	http.Redirect(w, r, "/tags", http.StatusSeeOther)
}

// HandleTagCreate creates a new tag.
func (s *Server) HandleTagCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	color := r.FormValue("color")
	if color == "" {
		color = "#206bc4"
	}
	if name == "" {
		http.Error(w, "Tag name is required", http.StatusBadRequest)
		return
	}

	textColor := r.FormValue("text_color")
	if textColor == "" {
		textColor = "#ffffff"
	}
	newID, err := s.DB.CreateTagWithTextColor(name, color, textColor)
	wantsJSON := strings.Contains(r.Header.Get("Accept"), "application/json")
	if err != nil {
		log.Printf("tag create: %v", err)
		if wantsJSON {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"error":"Could not create tag (name may already exist)."}`))
			return
		}
		setFlash(w, "Could not create tag (name may already exist).")
	} else if wantsJSON {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"id":%d,"name":%q,"color":%q,"text_color":%q}`, newID, name, color, textColor)
		return
	} else {
		setFlash(w, "Tag created.")
	}

	ref := r.Header.Get("Referer")
	if ref == "" {
		ref = "/tags"
	}
	http.Redirect(w, r, ref, http.StatusSeeOther)
}

// HandleTagCheckUsage returns, for each tag_id in the form, which nodes use it.
// POST /tags/check-usage, Accept: application/json. Body: tag_ids=... repeated.
func (s *Server) HandleTagCheckUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	var ids []uint64
	for _, v := range r.Form["tag_ids"] {
		if id, err := strconv.ParseUint(v, 10, 64); err == nil {
			ids = append(ids, id)
		}
	}
	usage, err := s.DB.GetNodesUsingTags(ids)
	if err != nil {
		log.Printf("tag check usage: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// Build a JSON response: {"assignments":[{"tag_name":"X","node_name":"Y"},...]}
	var parts []string
	for _, entries := range usage {
		for _, e := range entries {
			parts = append(parts, fmt.Sprintf(`{"tag_name":%q,"node_name":%q}`, e.TagName, e.NodeName))
		}
	}
	fmt.Fprintf(w, `{"assignments":[%s]}`, strings.Join(parts, ","))
}

// HandleTagBulkDelete deletes multiple tags in one request (POST /tags/bulk-delete).
func (s *Server) HandleTagBulkDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	var count int
	for _, v := range r.Form["tag_ids"] {
		id, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			continue
		}
		if err := s.DB.DeleteTag(id); err != nil {
			log.Printf("tag bulk delete: %v", err)
			continue
		}
		count++
	}
	setFlash(w, fmt.Sprintf("Deleted %d tag(s).", count))
	http.Redirect(w, r, "/tags", http.StatusSeeOther)
}

// HandleTagDelete deletes a tag.
func (s *Server) HandleTagDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/tags/")
	idStr = strings.TrimSuffix(idStr, "/delete")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if err := s.DB.DeleteTag(id); err != nil {
		log.Printf("tag delete: %v", err)
	}
	setFlash(w, "Tag deleted.")

	ref := r.Header.Get("Referer")
	if ref == "" {
		ref = "/tags"
	}
	http.Redirect(w, r, ref, http.StatusSeeOther)
}
