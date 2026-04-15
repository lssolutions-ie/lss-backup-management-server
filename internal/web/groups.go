package web

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/lssolutions-ie/lss-management-server/internal/models"
)

type groupsPageData struct {
	PageData
	Groups []*models.ClientGroup
}

type groupFormPageData struct {
	PageData
	Group *models.ClientGroup
	Error string
}

func (s *Server) HandleGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.DB.ListClientGroups()
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}
	s.render(w, r, http.StatusOK, "groups.html", groupsPageData{
		PageData: s.newPageData(r),
		Groups:   groups,
	})
}

func (s *Server) HandleGroupNew(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.render(w, r, http.StatusOK, "group_form.html", groupFormPageData{
			PageData: s.newPageData(r),
		})
		return
	}

	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		s.render(w, r, http.StatusUnprocessableEntity, "group_form.html", groupFormPageData{
			PageData: s.newPageData(r),
			Error:    "Name is required.",
		})
		return
	}

	rank := r.FormValue("rank")
	gid, err := s.DB.CreateClientGroup(name, rank)
	if err != nil {
		log.Printf("group new: %v", err)
		s.render(w, r, http.StatusUnprocessableEntity, "group_form.html", groupFormPageData{
			PageData: s.newPageData(r),
			Error:    "Could not create group (name may already be taken).",
		})
		return
	}

	s.auditServer(r, "group_created", "info", "create", "group",
		strconv.FormatUint(gid, 10),
		"Created client group "+name,
		map[string]string{"name": name, "rank": rank})

	setFlash(w, "Group created.")
	http.Redirect(w, r, "/groups", http.StatusSeeOther)
}

func (s *Server) HandleGroupEdit(w http.ResponseWriter, r *http.Request) {
	group, ok := s.groupFromPath(w, r)
	if !ok {
		return
	}

	if r.Method == http.MethodGet {
		s.render(w, r, http.StatusOK, "group_form.html", groupFormPageData{
			PageData: s.newPageData(r),
			Group:    group,
		})
		return
	}

	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		s.render(w, r, http.StatusUnprocessableEntity, "group_form.html", groupFormPageData{
			PageData: s.newPageData(r),
			Group:    group,
			Error:    "Name is required.",
		})
		return
	}

	rank := r.FormValue("rank")
	if err := s.DB.UpdateClientGroup(group.ID, name, rank); err != nil {
		log.Printf("group edit: %v", err)
		s.render(w, r, http.StatusInternalServerError, "group_form.html", groupFormPageData{
			PageData: s.newPageData(r),
			Group:    group,
			Error:    "Could not update group.",
		})
		return
	}

	s.auditServer(r, "group_updated", "info", "update", "group",
		strconv.FormatUint(group.ID, 10),
		"Updated client group "+name,
		map[string]string{"name": name, "rank": rank})

	setFlash(w, "Group updated.")
	http.Redirect(w, r, "/groups", http.StatusSeeOther)
}

func (s *Server) HandleGroupDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	group, ok := s.groupFromPath(w, r)
	if !ok {
		return
	}

	if !s.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	count, err := s.DB.CountNodesInGroup(group.ID)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return
	}
	if count > 0 {
		setFlash(w, "This group has nodes assigned. Reassign or delete them first.")
		http.Redirect(w, r, "/groups", http.StatusSeeOther)
		return
	}

	if err := s.DB.DeleteClientGroup(group.ID); err != nil {
		log.Printf("group delete: %v", err)
		setFlash(w, "Could not delete group.")
		http.Redirect(w, r, "/groups", http.StatusSeeOther)
		return
	}

	s.auditServer(r, "group_deleted", "warn", "delete", "group",
		strconv.FormatUint(group.ID, 10),
		"Deleted client group "+group.Name,
		map[string]string{"name": group.Name})

	setFlash(w, "Group deleted.")
	http.Redirect(w, r, "/groups", http.StatusSeeOther)
}

func (s *Server) groupFromPath(w http.ResponseWriter, r *http.Request) (*models.ClientGroup, bool) {
	rest := strings.TrimPrefix(r.URL.Path, "/groups/")
	parts := strings.SplitN(rest, "/", 2)
	id, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return nil, false
	}
	group, err := s.DB.GetClientGroupByID(id)
	if err != nil {
		s.Fail(w, r, http.StatusInternalServerError, err, "Internal Server Error")
		return nil, false
	}
	if group == nil {
		http.NotFound(w, r)
		return nil, false
	}
	return group, true
}
