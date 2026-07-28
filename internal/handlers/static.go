package handlers

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// HTTPStatic serves static files from a local directory, with optional SPA fallback and directory browsing.
type HTTPStatic struct {
	Dir    string // Root directory path
	SPA    bool   // Enable SPA fallback to index.html for non-existent routes
	Index  string // Default index filename (default: "index.html")
	Browse bool   // Enable directory browsing
}

func (h *HTTPStatic) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	dir := strings.TrimSpace(h.Dir)
	if dir == "" {
		http.Error(w, "Static directory not configured", http.StatusInternalServerError)
		return
	}

	// If Dir points directly to a single file on disk, serve it directly
	if info, err := os.Stat(dir); err == nil && !info.IsDir() {
		http.ServeFile(w, r, dir)
		return
	}

	index := strings.TrimSpace(h.Index)
	if index == "" {
		index = "index.html"
	}

	// Clean requested URL path
	reqPath := filepath.Clean(r.URL.Path)
	if reqPath == "." || reqPath == "" {
		reqPath = "/"
	}

	// Determine absolute disk path
	fullPath := filepath.Join(dir, filepath.FromSlash(reqPath))

	// Guard against directory traversal attacks outside root directory
	rel, err := filepath.Rel(dir, fullPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	info, err := os.Stat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			if h.SPA {
				// SPA fallback: serve root index.html
				indexPath := filepath.Join(dir, index)
				if idxInfo, idxErr := os.Stat(indexPath); idxErr == nil && !idxInfo.IsDir() {
					http.ServeFile(w, r, indexPath)
					return
				}
			}
			http.NotFound(w, r)
			return
		}
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if info.IsDir() {
		// Try index file in directory
		indexPath := filepath.Join(fullPath, index)
		if idxInfo, idxErr := os.Stat(indexPath); idxErr == nil && !idxInfo.IsDir() {
			http.ServeFile(w, r, indexPath)
			return
		}

		if h.Browse {
			http.FileServer(http.Dir(dir)).ServeHTTP(w, r)
			return
		}

		if h.SPA {
			indexPath := filepath.Join(dir, index)
			if idxInfo, idxErr := os.Stat(indexPath); idxErr == nil && !idxInfo.IsDir() {
				http.ServeFile(w, r, indexPath)
				return
			}
		}

		http.NotFound(w, r)
		return
	}

	// Serve static file directly
	http.ServeFile(w, r, fullPath)
}
