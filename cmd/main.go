/*
Simple HTTP/S file server, defaults to serving on port 8080. Allows file
upload, download, and deletion. Folders can be deleted if empty.
Run with --help for full options
*/
package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spcnvdr/gopost/internal/auth"
	"github.com/spcnvdr/gopost/internal/certs"
	"github.com/spcnvdr/gopost/internal/files"
)

const Version = "mini server 0.1.4"

/*
File: a small struct to hold information about a file that can be easily
displayed in templates
*/
type File struct {
	Name  string
	Size  string
	Mode  string
	Date  string
	IsDir bool
}

/*
	Files is a slice holding information about each file in the destination

directory
*/
type Files []File

/*
Context is the struct containing all data passed to the template
*/
type Context struct {
	Title     string
	Directory string // Current directory user is in
	Parent    string // The parent directory
	Files     Files
}

// global variables for command line arguments
var (
	AUTH      bool
	CERT      string
	HOST      string
	KEY       string
	PASS      string
	PORT      string
	TLS       bool
	USER      string
	VERBOSE   bool
	VERSION   bool
	FILE_PATH string // folder to serve files from
)

// init is automatically called at start, setup cmd line args
func init() {

	// host/IP adddress
	flag.StringVar(&HOST, "ip", "0.0.0.0", "IP address to serve on, defaults to 0.0.0.0")
	flag.StringVar(&HOST, "i", "0.0.0.0", "IP shortcut")

	// version
	flag.BoolVar(&VERSION, "version", false, "Print program version")
	flag.BoolVar(&VERSION, "V", false, "Version shortcut")

	// port
	flag.StringVar(&PORT, "port", "8080", "Port to listen on, defaults to 8080")
	flag.StringVar(&PORT, "p", "8080", "Port shortcut")

	// enable TLS
	flag.BoolVar(&TLS, "tls", false, "Generate and use self-signed TLS cert/key")
	flag.BoolVar(&TLS, "t", false, "TLS shortcut")

	// Use custom TLS key
	flag.StringVar(&KEY, "key", "", "Use custom TLS Key, must also provide cert in PEM")
	flag.StringVar(&KEY, "k", "", "TLS key shortcut")

	// Use custom TLS cert
	flag.StringVar(&CERT, "cert", "", "Use custom TLS Cert, must also provide key")
	flag.StringVar(&CERT, "c", "", "TLS cert shortcut")

	// enable simple authentication
	flag.StringVar(&USER, "user", "", "Enable authentication with this username")
	flag.StringVar(&USER, "u", "", "Basic auth shortcut")

	// enable verbose mode
	flag.BoolVar(&VERBOSE, "verbose", false, "Enable verbose output")
	flag.BoolVar(&VERBOSE, "v", false, "Verbose shortcut")
}

func main() {
	// setup and parse command line arguments
	var cert, key string
	flag.Usage = printHelp
	flag.Parse()

	if VERSION {
		log.Fatalln(Version)
	}

	// Require folder argument to run
	if len(flag.Args()) == 0 {
		printUsage()
	}

	FILE_PATH = flag.Arg(0)

	// check path is a directory and can be accessed
	if err := files.CheckDir(FILE_PATH); err != nil {
		log.Fatalf("%v", err)
	}

	// make sure cert and key are given
	checkPem(CERT, KEY)

	// if generating our own self-signed TLS cert/key
	if TLS {
		certs.GenKeys(HOST)
		cert = "cert.pem"
		key = "key.pem"
	}

	// use provided cert and key,
	if len(CERT) > 0 && len(KEY) > 0 {
		cert = CERT
		key = KEY
	}

	// User enabled basic auth, get password interactively
	if len(USER) > 0 {
		AUTH = true
		PASS = auth.GetPass()
	}

	// setup our routes
	setupRoutes()

	// start server, bail if error
	serving := HOST + ":" + PORT
	if len(CERT) > 0 || TLS {
		// Set TLS preferences
		s := setupServerConfig(serving)

		fmt.Println(`If using a self-signed certificate, ignore "unknown certificate" warnings`)
		fmt.Printf("\nServing on: https://%s\n", formatURL(true, HOST, PORT))
		err := s.ListenAndServeTLS(cert, key)
		log.Fatal(err)

	} else {
		fmt.Printf("\nServing on: http://%s\n", formatURL(false, HOST, PORT))
		err := http.ListenAndServe(serving, nil)
		log.Fatal(err)
	}

}

// printUsage - Print a simple usage message and exit.
func printUsage() {
	fmt.Fprintf(os.Stderr, "usage: mini [-tv?V] [-c file] [-i host] [-k file] [-p port] [-u user] folder\n")
	fmt.Fprintf(os.Stderr, `Try 'mini --help' or 'mini -h' for more information`+"\n")
	os.Exit(1)
}

// printHelp - Print a custom detailed help message.
func printHelp() {

	fmt.Fprintf(os.Stderr, "Usage: mini [OPTION...] FOLDER\n")
	fmt.Fprintf(os.Stderr, "Serve the given folder via an HTTP/S server\n\n")
	fmt.Fprintf(os.Stderr, "  -c, --cert=CERT           Use the provided PEM cert for TLS, MUST also use -k\n")
	fmt.Fprintf(os.Stderr, "  -i, --ip=HOST             IP address to serve on; default 0.0.0.0\n")
	fmt.Fprintf(os.Stderr, "  -k, --key=KEY             Use provided PEM key for TLS, MUST also use -c\n")
	fmt.Fprintf(os.Stderr, "  -p, --port=PORT           Port to serve on: default 8080\n")
	fmt.Fprintf(os.Stderr, "  -t, --tls                 Generate and use self-signed TLS cert.\n")
	fmt.Fprintf(os.Stderr, "  -u, --user=USERNAME       Enable basic auth. with this username\n")
	fmt.Fprintf(os.Stderr, "  -v, --verbose             Enable verbose logging mode\n")
	fmt.Fprintf(os.Stderr, "  -?, --help                Show this help message\n")
	fmt.Fprintf(os.Stderr, "  -V, --version             Print program version\n")
	fmt.Fprintf(os.Stderr, "\n")
}

/*
checkPem ensures that either both a certificate an key file are given as
arugments or neither are given. A user must specify a ceertificate and key
file on the command line or neither.
*/
func checkPem(cert, key string) {
	if (len(cert) > 0 && len(key) == 0) || (len(cert) == 0 && len(key) > 0) {
		log.Fatal("Error: must provie both a key and certificate in PEM format!")
	}
}

// setupRoutes, helper function to configure routes and handlers
func setupRoutes() {
	// setup our routes
	http.HandleFunc("/", redirectRoot)
	http.HandleFunc("/get", getFile)
	http.HandleFunc("/upload", uploadFiles)
	http.HandleFunc("/view", viewDir)
	http.HandleFunc("/delete", deleteFile)
}

// setupServerConfig creates an http.Server configuration for the given host
func setupServerConfig(host string) http.Server {
	return http.Server{
		Addr: host,
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			},
		},
	}
}

/*
formatURL formats the URL before printing where the server is hosted
Don't show the port number if serving on the default port for the given
protocol, e.g. https://hostname.com instead of https://hostname.com:443
*/
func formatURL(tls bool, host, port string) string {
	if tls && port == "443" {
		return host
	} else if !tls && port == "80" {
		return host
	} else {
		return fmt.Sprintf("%s:%s", host, port)
	}
}

// sizeToStr converts a file size in bytes to a human friendy string.
func sizeToStr(n int64) string {
	if n == 0 {
		return "0B"
	}

	b := float64(n)
	units := []string{"B", "K", "M", "G", "T", "P", "E"}

	i := math.Floor(math.Log(b) / math.Log(1024))
	return strconv.FormatFloat((b/math.Pow(1024, i))*1, 'f', 1, 64) + units[int(i)]
}

/*
fileFunc is called on each file in the target directory and returns
a Files struct with the relevant information about each file.
*/
func fileFunc(path string) (Files, error) {
	var fs Files

	files, err := os.ReadDir(path)
	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		var f File

		finfo, err := file.Info()
		if err != nil {
			continue
		}

		f.Name = finfo.Name()
		f.Size = sizeToStr(finfo.Size())
		f.Mode = finfo.Mode().String()
		f.Date = finfo.ModTime().Format(time.UnixDate)
		f.IsDir = finfo.IsDir()
		fs = append(fs, f)
	}
	return fs, nil
}

/* Server helper functions and handlers */

/*
checkAuth is a helper function that check's a user's credential when
basic auth is enabled. Returns true if user successfully authenticated or
if basic auth is disabled, return false otherwise.
*/
func checkAuth(w http.ResponseWriter, r *http.Request) bool {
	if AUTH {
		user, pass, ok := r.BasicAuth()
		if !ok || (user != USER || !auth.CheckPass(pass, PASS)) {
			return false
		}
	}
	return true

}

/*
authFail sends a 401 unauthorized status code when a user fails to
authenticate
*/
func authFail(w http.ResponseWriter, r *http.Request) {
	if VERBOSE {
		log.Printf("CLIENT: %s PATH: %s: INCORRECT USERNAME/PASS\n",
			r.RemoteAddr, r.RequestURI)
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="api"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

// redirectRoot redirects server root to /view?dir=/.
func redirectRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/view?dir=/", http.StatusFound)
}

// getFile serves a single file requested via URL
func getFile(w http.ResponseWriter, r *http.Request) {
	// if basic auth, must be logged in to download
	if !checkAuth(w, r) {
		authFail(w, r)
		return
	}

	keys, ok := r.URL.Query()["file"]
	if !ok || len(keys[0]) < 1 {
		log.Println("Url Param 'key' is missing")
		redirectRoot(w, r)
	}

	file := keys[0]
	if strings.Contains(file, "..") {
		// prevent path traversal
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	path := filepath.Clean(filepath.Join(FILE_PATH, file))

	// Set header so user sees the original filename in the download box
	filename := filepath.Base(path)
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)

	if VERBOSE {
		log.Printf("CLIENT: %s DOWNLOAD: %s\n", r.RemoteAddr, path)
	}

	http.ServeFile(w, r, path)
}

/*
viewDir is called when a person clicks a directory link, displays files in
the directory.
*/
func viewDir(w http.ResponseWriter, r *http.Request) {
	// the HTML template to display files
	htmltemp := `<!DOCTYPE html>
	<html lang="en" dir="ltr">
		<head>
			<meta charset="utf-8">
			<meta name="viewport"
				content="width=device-width, initial-scale=1, shrink-to-fit=no">
			<meta name="description" content="Simple file server">
			<!-- prevent favicon requests -->
			<link rel="icon" type="image/png" href="data:image/png;base64,iVBORw0KGgo=">
			<title>{{ .Title }}</title>
			<style>
				tbody tr:nth-child(odd) {
					background-color: #eeeeee;
			  	}
				@media (min-width:960px) { 
					.upload-form {
						max-width: 40%;
					}
				}
			</style>
		</head>
		<body>
		<h2>{{.Title}}</h2>
		<p>
			<form enctype="multipart/form-data"
				action="/upload"
				method="POST"
				class="upload-form">
				<fieldset>
					<legend>Upload new file/files</legend>
					<input type="hidden" id="directory" type="text" name="directory" value="{{ .Directory }}">
					<input type="file" placeholder="Filename" name="file-upload" required multiple>
					<button type="submit">Upload</button>
				</fieldset>
			</form>
		</p>
		{{ if eq .Directory "/" }}
			<p></p>
		{{ else }}
		<p>
			<a href="/view?dir={{ .Parent }}">To Parent Directory</a>
		</p>
		{{ end }}
		<p>
		<table>
			<thead>
				<tr>
					<th>Filename</th>
					<th>Size</th>
					<th>Mode</th>
					<th>Last Modified</th>
					<th>Delete</th>
				</tr>
			</thead>
			<tbody>
				{{range .Files}}
					<tr>
						<td>
							{{ if .IsDir }}
								{{ if eq $.Directory  "/" }}
									<a href="/view?dir={{ .Name }}">{{ .Name }}/</a>
								{{ else }}
									<a href="/view?dir={{ $.Directory }}/{{ .Name }}">{{ .Name }}/</a>
								{{ end }}
							{{ else }}
								{{ if eq $.Directory  "/" }}
									<a download href="/get?file={{ .Name }}">{{ .Name }}</a>
									
								{{ else }}
									<a download href="/get?file={{ $.Directory }}/{{ .Name }}">{{ .Name }}</a>
								{{ end }}
							{{ end }}
						</td>
						<td>{{ .Size }}</td>
						<td>{{ .Mode }}</td>
						<td>{{ .Date}}</td>
						<td>
							<form action="/delete" method="POST" class="form-example">
								<div>
									<input type="hidden" id="directory" type="text" name="directory" value="{{ $.Directory }}">
									<input type="hidden" id="file" type="file" name="filename" value="{{ .Name }}">
									<input type="submit" value="Delete">
								</div>
							</form>
					  </td>
					</tr>
				{{ end }}
			</tbody>
		</table>
		</p>
		</body>
	</html>`

	// check basic auth if enabled
	if !checkAuth(w, r) {
		authFail(w, r)
		return
	}

	if VERBOSE {
		log.Printf("CLIENT: %s PATH: %s\n", r.RemoteAddr, r.RequestURI)
	}

	keys, ok := r.URL.Query()["dir"]

	if !ok || len(keys[0]) < 1 {
		log.Println("Url Param 'key' is missing")
		http.Redirect(w, r, "/view?dir=/", http.StatusFound)
		return
	}

	dir := filepath.Clean(keys[0])

	// Handle Windows paths, filepath is the OS independent way to handle paths
	dir = filepath.ToSlash(dir)

	// What is the parent for current folder?
	parent := filepath.Dir(dir)
	if parent == "." {
		parent = "/"
	}

	if strings.Contains(dir, "..") {
		// prevent path traversal
		http.Redirect(w, r, "/view?dir/", http.StatusFound)
		return
	}

	// create real path from the server's root folder and navigated folder
	path := filepath.Clean(filepath.Join(FILE_PATH, dir))

	// get list of files in directory
	f, err := fileFunc(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create data for templates, parse and execute template
	title := "Directory listing for " + dir
	context := Context{title, dir, parent, f}
	templates := template.Must(template.New("foo").Parse(htmltemp))

	if err := templates.Execute(w, context); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// uploadFile called when a user chooses a file and clicks the upload button.
func uploadFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// check basic auth if enabled
	if !checkAuth(w, r) {
		authFail(w, r)
		return
	}

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	uploadFiles := r.MultipartForm.File["file-upload"]

	dir := filepath.Clean(r.FormValue("directory"))
	if strings.Contains(dir, "..") {
		// prevent path traversal, redirect to home page
		http.Redirect(w, r, "/view?dir=/", http.StatusFound)
		return
	}

	for i := range uploadFiles {
		path := filepath.Clean(filepath.Join(FILE_PATH, dir, uploadFiles[i].Filename))

		file, err := uploadFiles[i].Open()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		defer file.Close()

		if err = files.CopyUploadFile(path, file); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		if VERBOSE {
			log.Printf("CLIENT: %s UPLOAD: %s\n", r.RemoteAddr, path)
		}

	}

	// reload the current page on successful upload
	http.Redirect(w, r, "view?dir="+dir, http.StatusFound)
}

/*
deleteFile is called when the delete button is clicked next to a file.
It checks that the file exists in the FILE_PATH directory and deletes it
if it exists.
*/
func deleteFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// check basic auth if enabled
	if !checkAuth(w, r) {
		authFail(w, r)
		return
	}
	// Get the name of the file to delete
	filename := r.FormValue("filename")
	if filename == "" {
		http.Error(w, "missing form value", http.StatusInternalServerError)
	}

	if strings.Contains(filename, "..") {
		// prevent path traversal deletion
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Get the directory to delete file from
	dir := r.FormValue("directory")

	// build path to the file
	path := filepath.Clean(filepath.Join(FILE_PATH, dir, filename))

	// Make sure file exists
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	// ignore errors
	os.Remove(path)

	if VERBOSE {
		log.Printf("CLIENT: %s DELETED: %s\n", r.RemoteAddr, path)
	}

	// reload the current page
	http.Redirect(w, r, "view?dir="+dir, http.StatusFound)
}
