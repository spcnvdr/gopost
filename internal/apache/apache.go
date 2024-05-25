// Package apache imitates a default Apache server running on Ubuntu
package apache

import (
	"log"
	"net/http"
	"text/template"

	"github.com/spcnvdr/gopost/internal/auth"
	"github.com/spcnvdr/gopost/internal/files"
)

type ApacheServer struct {
	query    string
	username string
	password string
	auth     bool
	verbose  bool
}

// NewApacheServer creates a new instance of ApacheServer
func NewApacheServer(username, password string, auth, verbose bool, query string) *ApacheServer {
	var as = new(ApacheServer)
	as.username = username
	as.password = password
	as.auth = auth
	as.verbose = verbose
	as.query = query
	return as
}

func (as *ApacheServer) SetupRoutes() {
	// setup our routes
	http.HandleFunc("/", as.Root)
	http.HandleFunc("/icons/ubuntu-logo.png", as.GetIcon)
}

func (as *ApacheServer) setHeaders(w http.ResponseWriter) {
	w.Header().Add("Server", "Apache/2.4.54 (Ubuntu)")
	w.Header().Add("Accept-Ranges", "bytes")
	w.Header().Add("Etag", "29af-5db4c92a77a00")
	w.Header().Add("Last-Modified", "Mon, 28 Mar 2022 19:46:48 GMT")

}

// the Root route is the index page for uploads. It behave like a default
// Apache site except that it accepts multiple file uploads via files POST
// parameter
func (as *ApacheServer) Root(w http.ResponseWriter, r *http.Request) {
	as.setHeaders(w)
	// check basic auth if enabled
	if !auth.CheckAuth(w, r, as.username, as.password, as.auth) {
		auth.AuthFail(w, r, as.verbose)
		return
	}

	if r.Method != "POST" {
		if as.verbose {
			log.Printf("CLIENT: %s %s: %s\n", r.RemoteAddr, r.Method, r.RequestURI)
		}

		if r.Method == "HEAD" || r.Method == "TRACE" {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// if they requast anything that isn't the root, respond with 404
		if r.URL.Path != "/" {
			as.NotFound(w, r)
			return
		}

		// parse and execute Apache home template
		as.Index(w, r)
		return
	}

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	// prevents a panic when scanned with nmap
	if r.MultipartForm == nil {
		return
	}

	// expect uploads to use the query string passed to constructor
	uploadFiles := r.MultipartForm.File[as.query]

	for i := range uploadFiles {
		path := "./" + uploadFiles[i].Filename

		file, err := uploadFiles[i].Open()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		defer file.Close()

		if err = files.CopyUploadFile(path, file); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		if as.verbose {
			log.Printf("CLIENT: %s UPLOAD: %s\n", r.RemoteAddr, path)
		}

	}
}

// serve the Ubuntu icon on the index page manually
func (as *ApacheServer) GetIcon(w http.ResponseWriter, r *http.Request) {
	as.setHeaders(w)

	// if basic auth, must be logged in to download
	if !auth.CheckAuth(w, r, as.username, as.password, as.auth) {
		auth.AuthFail(w, r, as.verbose)
		return
	}

	path := "../resources/static/images/ubuntu-logo.png"

	// Set header so user sees the original filename in the download box
	//filename := filepath.Base(path)
	//w.Header().Set("Content-Disposition", "attachment; filename="+filename)

	if as.verbose {
		log.Printf("CLIENT: %s DOWNLOAD: %s\n", r.RemoteAddr, path)
	}

	http.ServeFile(w, r, path)
}

func (as *ApacheServer) NotFound(w http.ResponseWriter, r *http.Request) {
	templates := template.Must(template.ParseFiles("../resources/templates/404.html"))
	w.WriteHeader(http.StatusNotFound)
	if err := templates.Execute(w, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (as *ApacheServer) Index(w http.ResponseWriter, r *http.Request) {
	templates := template.Must(template.ParseFiles("../resources/templates/index.html"))
	if err := templates.Execute(w, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
