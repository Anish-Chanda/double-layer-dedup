package api

import (
	"encoding/json"
	"net/http"

	"github.com/Anish-Chanda/double-layer-dedup/internal/service"
	"github.com/go-chi/chi/v5"
)

// HealthHandler checks if the server is alive
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// UploadHandler handles POST /api/files
func UploadHandler(w http.ResponseWriter, r *http.Request) {
	resp, err := service.SaveFile(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// DownloadHandler handles GET /api/files/{id}
func DownloadHandler(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	err := service.StreamFile(w, r, id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
	}
}
