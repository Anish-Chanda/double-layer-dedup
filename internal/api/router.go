package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

func NewRouter() http.Handler {
	r := chi.NewRouter()

	r.Get("/api/health", HealthHandler)
	r.Post("/api/files", UploadHandler)
	r.Get("/api/files/{id}", DownloadHandler)

	return r
}
