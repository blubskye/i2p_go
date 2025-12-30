// Package eepsite implements an HTTP server for hosting I2P websites (eepsites).
package eepsite

import (
	"fmt"
	"html/template"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Server is an eepsite HTTP server.
type Server struct {
	mu sync.RWMutex

	config   *Config
	listener net.Listener
	server   *http.Server
	handler  http.Handler
	running  bool
	done     chan struct{}

	// Stats
	requestCount int64
	bytesServed  int64
	startTime    time.Time
}

// Config holds eepsite configuration.
type Config struct {
	// Root directory for serving files
	RootDir string
	// Index file names to try
	IndexFiles []string
	// Enable directory listing
	DirectoryListing bool
	// Custom error pages directory
	ErrorPagesDir string
	// Log requests
	LogRequests bool
	// Server name header
	ServerName string
	// Custom headers
	Headers map[string]string
}

// DefaultConfig returns the default eepsite configuration.
func DefaultConfig() *Config {
	return &Config{
		RootDir:          "./www",
		IndexFiles:       []string{"index.html", "index.htm", "default.html"},
		DirectoryListing: true,
		ServerName:       "I2P-Eepsite/1.0",
		Headers:          make(map[string]string),
	}
}

// NewServer creates a new eepsite server.
func NewServer(config *Config) *Server {
	if config == nil {
		config = DefaultConfig()
	}

	s := &Server{
		config:    config,
		done:      make(chan struct{}),
		startTime: time.Now(),
	}

	s.handler = s.createHandler()
	return s
}

// createHandler creates the HTTP handler.
func (s *Server) createHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requestCount++
		s.mu.Unlock()

		// Add custom headers
		for k, v := range s.config.Headers {
			w.Header().Set(k, v)
		}
		w.Header().Set("Server", s.config.ServerName)

		// Log request if enabled
		if s.config.LogRequests {
			fmt.Printf("[%s] %s %s %s\n", time.Now().Format(time.RFC3339), r.Method, r.URL.Path, r.RemoteAddr)
		}

		// Serve the request
		s.serveRequest(w, r)
	})
}

// serveRequest serves an HTTP request.
func (s *Server) serveRequest(w http.ResponseWriter, r *http.Request) {
	// Clean and validate path
	urlPath := path.Clean(r.URL.Path)
	if urlPath == "" {
		urlPath = "/"
	}

	// Prevent directory traversal
	if strings.Contains(urlPath, "..") {
		s.serveError(w, r, http.StatusForbidden)
		return
	}

	// Build file path
	filePath := filepath.Join(s.config.RootDir, filepath.FromSlash(urlPath))

	// Check if file exists
	info, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		s.serveError(w, r, http.StatusNotFound)
		return
	}
	if err != nil {
		s.serveError(w, r, http.StatusInternalServerError)
		return
	}

	// Handle directories
	if info.IsDir() {
		// Try index files
		for _, indexFile := range s.config.IndexFiles {
			indexPath := filepath.Join(filePath, indexFile)
			if _, err := os.Stat(indexPath); err == nil {
				s.serveFile(w, r, indexPath)
				return
			}
		}

		// Show directory listing if enabled
		if s.config.DirectoryListing {
			s.serveDirectory(w, r, filePath, urlPath)
			return
		}

		s.serveError(w, r, http.StatusForbidden)
		return
	}

	// Serve the file
	s.serveFile(w, r, filePath)
}

// serveFile serves a file.
func (s *Server) serveFile(w http.ResponseWriter, r *http.Request, filePath string) {
	file, err := os.Open(filePath)
	if err != nil {
		s.serveError(w, r, http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// Get file info
	info, err := file.Stat()
	if err != nil {
		s.serveError(w, r, http.StatusInternalServerError)
		return
	}

	// Set content type
	ext := filepath.Ext(filePath)
	contentType := mime.TypeByExtension(ext)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)

	// Set content length
	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))

	// Set last modified
	w.Header().Set("Last-Modified", info.ModTime().UTC().Format(http.TimeFormat))

	// Handle conditional requests
	if r.Method == http.MethodHead {
		return
	}

	// Copy file to response
	written, _ := io.Copy(w, file)

	s.mu.Lock()
	s.bytesServed += written
	s.mu.Unlock()
}

// serveDirectory serves a directory listing.
func (s *Server) serveDirectory(w http.ResponseWriter, r *http.Request, dirPath, urlPath string) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		s.serveError(w, r, http.StatusInternalServerError)
		return
	}

	// Sort entries: directories first, then files
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir() != entries[j].IsDir() {
			return entries[i].IsDir()
		}
		return entries[i].Name() < entries[j].Name()
	})

	// Build directory listing
	type fileEntry struct {
		Name    string
		Size    string
		ModTime string
		IsDir   bool
	}

	files := make([]fileEntry, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		size := ""
		if !entry.IsDir() {
			size = formatSize(info.Size())
		}

		files = append(files, fileEntry{
			Name:    entry.Name(),
			Size:    size,
			ModTime: info.ModTime().Format("2006-01-02 15:04"),
			IsDir:   entry.IsDir(),
		})
	}

	// Render template
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	tmpl := template.Must(template.New("dir").Parse(directoryTemplate))
	tmpl.Execute(w, map[string]interface{}{
		"Path":    urlPath,
		"Files":   files,
		"HasParent": urlPath != "/",
	})
}

// serveError serves an error page.
func (s *Server) serveError(w http.ResponseWriter, r *http.Request, status int) {
	// Try custom error page
	if s.config.ErrorPagesDir != "" {
		errorFile := filepath.Join(s.config.ErrorPagesDir, fmt.Sprintf("%d.html", status))
		if _, err := os.Stat(errorFile); err == nil {
			w.WriteHeader(status)
			s.serveFile(w, r, errorFile)
			return
		}
	}

	// Default error page
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>%d %s</title></head>
<body>
<h1>%d %s</h1>
<hr>
<p><i>%s</i></p>
</body>
</html>`, status, http.StatusText(status), status, http.StatusText(status), s.config.ServerName)
}

// Start starts the server with the given listener.
func (s *Server) Start(listener net.Listener) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}

	s.listener = listener
	s.server = &http.Server{
		Handler:      s.handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}
	s.running = true
	s.mu.Unlock()

	go s.server.Serve(listener)
	return nil
}

// StartLocal starts the server on a local address (for testing).
func (s *Server) StartLocal(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	return s.Start(listener)
}

// Stop stops the server.
func (s *Server) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	close(s.done)
	s.mu.Unlock()

	return s.server.Close()
}

// Stats returns server statistics.
func (s *Server) Stats() (requests, bytesServed int64, uptime time.Duration) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.requestCount, s.bytesServed, time.Since(s.startTime)
}

// formatSize formats a file size for display.
func formatSize(size int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case size >= GB:
		return fmt.Sprintf("%.1f GB", float64(size)/float64(GB))
	case size >= MB:
		return fmt.Sprintf("%.1f MB", float64(size)/float64(MB))
	case size >= KB:
		return fmt.Sprintf("%.1f KB", float64(size)/float64(KB))
	default:
		return fmt.Sprintf("%d B", size)
	}
}

// directoryTemplate is the HTML template for directory listings.
const directoryTemplate = `<!DOCTYPE html>
<html>
<head>
<title>Index of {{.Path}}</title>
<style>
body { font-family: monospace; margin: 20px; }
h1 { color: #333; }
table { border-collapse: collapse; width: 100%; max-width: 800px; }
th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }
th { background: #f5f5f5; }
a { color: #0066cc; text-decoration: none; }
a:hover { text-decoration: underline; }
.dir { color: #0066cc; font-weight: bold; }
.size { text-align: right; color: #666; }
.date { color: #666; }
</style>
</head>
<body>
<h1>Index of {{.Path}}</h1>
<table>
<tr><th>Name</th><th class="size">Size</th><th>Last Modified</th></tr>
{{if .HasParent}}<tr><td><a href="../">..</a></td><td></td><td></td></tr>{{end}}
{{range .Files}}
<tr>
<td>{{if .IsDir}}<a href="{{.Name}}/" class="dir">{{.Name}}/</a>{{else}}<a href="{{.Name}}">{{.Name}}</a>{{end}}</td>
<td class="size">{{.Size}}</td>
<td class="date">{{.ModTime}}</td>
</tr>
{{end}}
</table>

<footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px;">
<p>Powered by <a href="https://github.com/blubskye/i2p_go">i2p_go</a> - I2P Router Implementation in Go</p>
</footer>
</body>
</html>`
