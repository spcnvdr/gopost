package auth

import (
	"bufio"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

/* Basic auth helper functions */

/*
checkAuth is a helper function that check's a user's credential when
basic auth is enabled. Returns true if user successfully authenticated or
if basic auth is disabled, return false otherwise.
*/
func CheckAuth(w http.ResponseWriter, r *http.Request, username, password string, auth bool) bool {
	if auth {
		user, pass, ok := r.BasicAuth()
		if !ok || (user != username || !CheckPass(pass, password)) {
			return false
		}
	}
	return true

}

/*
authFail sends a 401 unauthorized status code when a user fails to
authenticate
*/
func AuthFail(w http.ResponseWriter, r *http.Request, verbose bool) {
	if verbose {
		log.Printf("CLIENT: %s PATH: %s: INCORRECT USERNAME/PASS\n",
			r.RemoteAddr, r.RequestURI)
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="api"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

/*
GetPass - Get password interactively from stdin,
keep retrying until input matches.
NOTE: We could probably come up with a better way to hash passwords,
but IDK if it really matters.
*/
func GetPass() string {
	reader := bufio.NewReader(os.Stdin)
	p1, p2 := "1", "2"

	// emulate a do-while to get and check that passwords entered match
	for bad := true; bad; bad = (p1 != p2) {
		//fmt.Printf("\nInput passwords did not match! Try again...\n")
		fmt.Print("\nEnter password: ")
		p1, _ = reader.ReadString('\n')
		fmt.Print("Enter password again: ")
		p2, _ = reader.ReadString('\n')
	}

	sha512 := sha512.New()
	sha512.Write([]byte(strings.TrimSpace(p1)))

	return base64.StdEncoding.EncodeToString(sha512.Sum(nil))
}

// CheckPass checks the input password against the one setup on cmd line.
func CheckPass(input, password string) bool {
	sha := sha512.New()
	sha.Write([]byte(input))
	inpass := base64.StdEncoding.EncodeToString(sha.Sum(nil))
	return inpass == password
}
