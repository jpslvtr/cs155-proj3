/*
 * CS155 Project 3
 * Part 4. Monster-in-the-Middle Attack
 *
 * Http_server.go
 * When compiled, this code will simulate the behavior of an oblivious
 * HTTP server. HTTPS (and HSTS) are not supported, and therefore this server
 * Has no certificate - not a good idea!
 *
 * Note: to aid your debugging, responses from the HTTP server are in ALL CAPS
*/

package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

var (
	logger = log.New(os.Stdout, "", 0)
	debug  = log.New(ioutil.Discard, "", log.Lshortfile) // Change ioutil.Discard to os.Stdout for debugging output
)

// Constants for handling logins. In an actual HTTP server this would be
// handled by connecting to a database - this is just a simplification!
const (
	SUPERSECRETCOOKIENAME  = "session_id"
	SUPERSECRETCOOKIEVALUE = "IReallyLikeSecureCookies"
	USERNAME               = "Sabrina"
	PASSWORD               = "PleaseComeBack"
)

/*
main
Parameters: None
Returns: None

Driver function. Does URL routing by calling HandleFunc first, i.e. it maps
endpoints on bank.com (such as /login) to a function which handles the
endpoint (LoginPage in this example). Then, Go's HTTP library serves all
incoming requests.
*/
func main() {
	http.HandleFunc("/", HomePage)
	http.HandleFunc("/login", LoginPage)
	http.HandleFunc("/transfer", TransferMoney)
	http.HandleFunc("/logout", Logout)
	logger.Fatal(http.ListenAndServe(":80", nil))
}

/*
HomePage
Parameters: response - a ResponseWriter interface; request - an incoming
HTTP request. The two variables are explained in greater detail in the
comments of Logout above.
Returns: None

Serves the / endpoint of bank.com.
On an incoming request, checks for a cookie and whether it is valid.
If all goes well, the client gets the (rather rudimentary) login page.
*/
func HomePage(response http.ResponseWriter, request *http.Request) {
	// Inspecting the request header might be useful for debugging your MITM.
	debug.Println(request.Header)

	if loggedIn(request) {
		addCookie(response, "AnotherCookie", "WeAreTrackingYou O_O")
		respond(response, "WELCOME TO BANK.COM")
	} else {
		respond(response, "INVALID COOKIE")
	}
}

/*
LoginPage
Parameters: response - a ResponseWriter interface; request - an incoming
HTTP request. The two variables are explained in greater detail in the
comments of Logout above.
Returns: None

Serves the /login endpoint of bank.com.
On an incoming request, it will check for a form with the username and
password. If they match the credentials hard-coded at the top of this file
as constants, the server will set a login cookie in its response.
*/
func LoginPage(response http.ResponseWriter, request *http.Request) {
	debug.Println(request.Header)

	if request.Method != "POST" {
		http.Error(response, "THIS IS THE LOGIN PAGE", 405)
		return
	}
	// Check: does the incoming request have a form with
	// the username and password filled in?
	if err := request.ParseForm(); err != nil {
		logger.Print("Error parsing form:", err)
		respond(response, "INVALID FORM")
		return
	}
	username := request.FormValue("username")
	password := request.FormValue("password")
	// Check if credentials match.
	if username == USERNAME && PASSWORD == password {
		addCookie(response, SUPERSECRETCOOKIENAME, SUPERSECRETCOOKIEVALUE)
		respond(response, "LOGIN SUCCESSFUL. HERE IS A COOKIE")
	} else {
		respond(response, "INVALID CREDENTIALS")
	}
}

/*
TransferMoney
Parameters: response - a ResponseWriter interface; request - an incoming
HTTP request. The two variables are explained in greater detail in the
comments of Logout above.
Returns: None

Serves the /transfer endpoint of bank.com.
Takes an incoming request, and checks if the request's cookie is valid. If so,
the request's form is parsed. Finally, if parsed without errors, the function
pretends to transfer money from the sender to the recipient.
*/
func TransferMoney(response http.ResponseWriter, request *http.Request) {
	debug.Println(request.Header)

	if request.Method != "POST" {
		http.Error(response, "TRANSFER MONEY SECURELY", 405)
		return
	}

	if !loggedIn(request) {
		http.Error(response, "TRANSFER MONEY SECURELY", 401)
		return
	}
	// Check: does the incoming request have a form with
	// the sender, recipient, and amount filled in for
	// transferring money? Also, in Golang, you can declare and
	// initialize the variable you will condition on in the head
	// of an if statement!
	if err := request.ParseForm(); err != nil {
		logger.Print("Error parsing form:", err)
		respond(response, "INVALID FORM")
		return
	}
	// Note: prior to calling ParseForm, the form in the HTTP
	// request is stored as a sequence of bytes. ParseForm
	// interprets that into a key-value data structure. You can
	// obtain the value for a key with FormValue.
	username := request.FormValue("from")
	to := request.FormValue("to")
	amount := request.FormValue("amount")
	// Foolproofing: FormValue returns the empty string if the
	// key (its parameter) was not found. In Golang, string does
	// not auto-cast as bool, unlike Python.
	if username == "" || to == "" || amount == "" {
		logger.Print("Form is missing required values")
		respond(response, "FORM IS MISSING REQUIRED VALUES")
		return
	}
	// No bank accounts were harmed in the production
	// of this starter code. :)
	logger.Printf("%s sent $%s to %s", username, amount, to)
	respond(response, fmt.Sprintf("%s SENT $%s TO %s", username, amount, to))
}


/*
Logout
Parameters: response - a ResponseWriter interface. Anything written to it
by io.WriteString will be in the request body as plain text; request - an
incoming HTTP request, represented as a struct. Some of its member variables
are Method (used below), URL, Header, Body, and Form.
Returns: None

Serves the /logout endpoint of bank.com.
Takes an incoming HTTP request and logs the user out, but this is again a
simplification. Regardless of whether the request was a GET or a POST, the
function just writes text to the request body.
*/
func Logout(response http.ResponseWriter, request *http.Request) {
	debug.Println(request.Header)

	if request.Method != "POST" {
		http.Error(response, "PLEASE SEND A POST REQUEST", 405)
		return
	}
	// Invalidate the cookie by setting a blank value and old expiration.
	c := &http.Cookie{
		Name:    SUPERSECRETCOOKIENAME,
		Value:   "",
		Expires: time.Unix(0, 0),
	}
	http.SetCookie(response, c)
	respond(response, "LOGOUT SUCCESSFUL")
}

/*
addCookie
Parameters: response - a ResponseWriter interface; name and value - strings
for the name-value pair in the cookie.
Returns: None

Helper function for LoginPage (which serves /login). If the user's credentials
are correct, this function adds a cookie to be set on the user's browser in
the HTTP response.
*/
func addCookie(response http.ResponseWriter, name string, value string) {
	// Login cookie expires in a day from now.
	expire := time.Now().AddDate(0, 0, 1)
	// An HTTP cookie in Go is just a struct which can be sent in the response
	// with SetCookie. Just remember to give a pointer to the struct,
	// instead of a copy.
	cookie := http.Cookie{
		Name:    name,
		Value:   value,
		Expires: expire,
	}
	http.SetCookie(response, &cookie)
}

/*
loggedIn
Writes a message as the HTTP response.
*/
func respond(r http.ResponseWriter, msg string) {
	_, err := io.WriteString(r, msg)
	if err != nil {
		logger.Panic(err)
	}
}

/*
loggedIn
Checks the cookies to see if the user is logged in.
*/
func loggedIn(r *http.Request) bool {
	cookie, err := r.Cookie(SUPERSECRETCOOKIENAME)
	if err == http.ErrNoCookie {
		logger.Print("No cookie provided")
		return false
	} else if err != nil {
		logger.Panic(err)
	}
	return cookie.Value == SUPERSECRETCOOKIEVALUE
}
