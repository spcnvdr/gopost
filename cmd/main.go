/*
Simple HTTP/S file server, defaults to serving on port 8080. Allows file
upload, download, and deletion. Folders can be deleted if empty.
Run with --help for full options
*/
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/spcnvdr/gopost/internal/apache"
	"github.com/spcnvdr/gopost/internal/auth"
	"github.com/spcnvdr/gopost/internal/certs"
)

const Version = "gopost 0.0.1"

// global variables for command line arguments
var (
	AUTH      bool
	CERT      string
	HOST      string
	KEY       string
	PASS      string
	PORT      string
	QUERY     string
	SERVE     string
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

	// query string to use for file upload
	flag.StringVar(&QUERY, "query", "files", "The parameter to use for file uploads")
	flag.StringVar(&QUERY, "q", "files", "Query shortut")

	// enable TLS
	flag.BoolVar(&TLS, "tls", false, "Generate and use self-signed TLS cert/key")
	flag.BoolVar(&TLS, "t", false, "TLS shortcut")

	flag.StringVar(&SERVE, "serve", "", "Serve files from FOLDER for downloading")
	flag.StringVar(&SERVE, "s", "", "Serve shortcut")

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

	as := apache.NewApacheServer(USER, PASS, AUTH, VERBOSE, QUERY)

	if SERVE != "" {
		setupDownloadRoutes(SERVE)
	} else {
		as.SetupRoutes()
	}

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

// printHelp - Print a custom detailed help message.
func printHelp() {

	fmt.Fprintf(os.Stderr, "Usage: gopost [OPTION...]\n")
	fmt.Fprintf(os.Stderr, "HTTP/S server that accepts uploads or serves folder for downloads\n\n")
	fmt.Fprintf(os.Stderr, "  -c, --cert=CERT           Use the provided PEM cert for TLS, MUST also use -k\n")
	fmt.Fprintf(os.Stderr, "  -i, --ip=HOST             IP address to serve on; default 0.0.0.0\n")
	fmt.Fprintf(os.Stderr, "  -k, --key=KEY             Use provided PEM key for TLS, MUST also use -c\n")
	fmt.Fprintf(os.Stderr, "  -p, --port=PORT           Port to serve on: default 8080\n")
	fmt.Fprintf(os.Stderr, "  -q, --query=STRING        The parameter name to expect file uploads to use in request body\n")
	fmt.Fprintf(os.Stderr, "  -s  --serve=FOLDER        Serve FOLDER for downloads instead of uploads\n")
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

// setupUploadRoutes, helper function to configure routes and handlers
// func setupUploadRoutes() {
// 	// setup our routes
// 	http.HandleFunc("/", root)
// 	http.HandleFunc("/icons/ubuntu-logo.png", getIcon)
// }

// setupDownloadRoutes sets up the routes when the server is used for downloads
func setupDownloadRoutes(root string) {
	http.Handle("/", http.StripPrefix("/", auth.BasicAuth(http.FileServer(http.Dir(root)), USER, PASS, AUTH, VERBOSE)))
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
