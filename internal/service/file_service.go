package service

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/Anish-Chanda/double-layer-dedup/internal/db"
	"github.com/google/uuid"
)

const uploadDir = "./uploads"

var DB *db.Client // Should be set from main.go

// SaveFile saves uploaded file to disk and inserts metadata into Postgres
func SaveFile(r *http.Request) (map[string]string, error) {
	r.ParseMultipartForm(10 << 20)
	file, handler, err := r.FormFile("file")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	id := uuid.New().String()
	filename := handler.Filename
	storedName := id + "_" + filename
	dst := filepath.Join(uploadDir, storedName)

	out, err := os.Create(dst)
	if err != nil {
		return nil, err
	}
	defer out.Close()

	_, err = io.Copy(out, file)
	if err != nil {
		return nil, err
	}

	// Save metadata to Postgres
	fileID, err := DB.CreateFile("rest-uploader", storedName) // Use actual ownerID in real app
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"file_id": fileID,
		"name":    filename,
		"status":  "uploaded",
	}, nil
}

// StreamFile streams file content from disk using file_id
func StreamFile(w http.ResponseWriter, r *http.Request, fileID string) error {
	// Lookup filename from DB
	chunks, err := DB.GetFileChunkHashes(fileID)
	if err != nil {
		return errors.New("file not found in DB")
	}

	// Reconstruct file from chunks (simplified: assume 1:1 filename here)
	// You might use chunk hashes to find the actual files in S3 or disk
	filename := fileID + "_restored.txt"
	tempPath := filepath.Join(uploadDir, filename)
	out, err := os.Create(tempPath)
	if err != nil {
		return err
	}
	defer out.Close()

	for _, chunk := range chunks {
		chunkPath := filepath.Join(uploadDir, chunk)
		data, err := os.ReadFile(chunkPath)
		if err != nil {
			return err
		}
		out.Write(data)
	}

	// Stream to client
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	http.ServeFile(w, r, tempPath)
	return nil
}
