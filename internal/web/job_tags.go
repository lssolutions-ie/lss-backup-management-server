package web

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

type jobTagsPageData struct {
	PageData
	JobTags []*models.JobTag
}

type jobTagEditPageData struct {
	PageData
	Tag   *models.JobTag
	Error string
}

func (s *Server) HandleJobTags(w http.ResponseWriter, r *http.Request) {
	tags, err := s.DB.ListJobTags()
	if err != nil {
		log.Printf("job tags: list: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	s.render(w, r, http.StatusOK, "job_tags.html", jobTagsPageData{
		PageData: s.newPageData(r),
		JobTags:  tags,
	})
}

func (s *Server) HandleJobTagCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Error(w, "Name required", http.StatusBadRequest)
		return
	}
	color := r.FormValue("color")
	textColor := r.FormValue("text_color")
	prio, _ := strconv.ParseUint(r.FormValue("priority"), 10, 8)
	if _, err := s.DB.CreateJobTag(name, color, textColor, uint8(prio)); err != nil {
		log.Printf("job tag create: %v", err)
		setFlash(w, "Could not create tag (name may already exist).")
	} else {
		setFlash(w, "Job tag created.")
	}
	http.Redirect(w, r, "/job-tags", http.StatusSeeOther)
}

func (s *Server) HandleJobTagEdit(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/job-tags/")
	idStr = strings.TrimSuffix(idStr, "/edit")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	tags, err := s.DB.ListJobTags()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	var tag *models.JobTag
	for _, t := range tags {
		if t.ID == id {
			tag = t
			break
		}
	}
	if tag == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodGet {
		s.render(w, r, http.StatusOK, "job_tag_edit.html", jobTagEditPageData{
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
	textColor := r.FormValue("text_color")
	prio, _ := strconv.ParseUint(r.FormValue("priority"), 10, 8)
	if err := s.DB.UpdateJobTag(id, name, color, textColor, uint8(prio)); err != nil {
		log.Printf("job tag edit: %v", err)
	}
	setFlash(w, "Job tag updated.")
	http.Redirect(w, r, "/job-tags", http.StatusSeeOther)
}

func (s *Server) HandleJobTagDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/job-tags/")
	idStr = strings.TrimSuffix(idStr, "/delete")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.DB.DeleteJobTag(id); err != nil {
		log.Printf("job tag delete: %v", err)
	}
	setFlash(w, "Job tag deleted.")
	http.Redirect(w, r, "/job-tags", http.StatusSeeOther)
}
