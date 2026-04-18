package web

import (
	"encoding/json"
	"net/http"
)

// HandleNodesListJSON returns a simple JSON list of all nodes for dropdowns.
func (s *Server) HandleNodesListJSON(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.DB.ListNodesWithStatus(nil)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	type nodeItem struct {
		ID   uint64 `json:"id"`
		Name string `json:"name"`
		UID  string `json:"uid"`
	}
	var items []nodeItem
	for _, n := range nodes {
		items = append(items, nodeItem{ID: n.ID, Name: n.Name, UID: n.UID})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"nodes": items})
}
