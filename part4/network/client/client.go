/*
CS155 Project 3
Part 4. Monster-in-the-Middle Attack

client.go
When compiled, this code will simulate the behavior of an oblivious client
that will fall victim to your monster-in-the-middle. For grading purposes,
feel free to test your MITM on this client. It will perform actions that
correspond to most of the requirements in the spec, but perhaps not all!
*/

package main

import (
	"context"
	"fmt"
	"golang.org/x/net/publicsuffix"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"time"
)

var (
	logger = log.New(os.Stdout, "Client: ", 0)
)

/*
ClientLogin
Parameters: None
Returns: A string representing the cookie name(s) and value(s) given
to this client by fakebank.com, in the format Name=Value.

Attempts to log in to fakebank.com with a POST request. If successful,
the function will also print the cookies and HTML returned by fakebank.com.
*/
func ClientLogin(client *http.Client) {
	logger.Println("Attempting login")
	response, err := client.PostForm("http://fakebank.com/login",
		url.Values{"username": {"Sabrina"},
			"password": {"PleaseComeBack"}})

	// Note that error handling in Golang is different from most other
	// languages. Instead of a try-catch structure, a function will return
	// an error alongside its actual return value.
	if err != nil {
		logger.Panic(err)
	} else {
		logger.Println("Successfully logged in")
	}

	// Statements prefixed with "defer" will not execute until the surrounding
	// function returns; hence the line below will run when ClientLogin returns.
	defer response.Body.Close()

	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}
	logger.Println("Login Response:", string(bodyBytes))
}

/*
ClientGetMainPage
Parameters: cookieString, a string representing the cookie given to the
client by fakebank.com. This is the return value of ClientLogin.
Returns: None

Uses the cookie supplied by ClientLogin to send a GET request to fakebank.com's
main page. Prints the HTML within fakebank.com's HTTP response.
*/
func ClientGetMainPage(client *http.Client) {
	logger.Println("Getting homepage")

	response, err := client.Get("http://fakebank.com/")
	if err != nil {
		logger.Panic(err)
	} else {
		logger.Println("Successfully retrieved homepage")
	}
	// Everything below has the same structure as ClientLogin.
	defer response.Body.Close()
	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}
	logger.Println("Main Page Response:", string(bodyBytes))
}

/*
ClientTransfer
Parameters: cookieString, a string representing the cookie given to the
client by fakebank.com. This is the return value of ClientLogin.
Returns: None

Uses the cookie supplied by ClientLogin to send a POST request containing
a form to fakebank.com's /transfer endpoint. Prints the HTML in fakebank.com's response.
*/
func ClientTransfer(client *http.Client) {
	logger.Println("Transferring from sabrina to jensen")

	newForm := url.Values{}
	newForm.Set("from", "sabrina")
	newForm.Set("to", "jensen")
	newForm.Set("amount", "1000")

	response, err := client.PostForm("http://fakebank.com/transfer", newForm)
	if err != nil {
		logger.Panic(err)
	} else {
		logger.Println("Successfully transferred")
	}
	defer response.Body.Close()
	// ...and in the response body, too.
	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		panic(err)
	}
	logger.Println("Transfer Page Response:", string(bodyBytes))
}

/*
ClientLogout
Parameters: cookieString, a string representing the cookie given to the
client by fakebank.com. This is the return value of ClientLogin.
Returns: None

Uses the cookie supplied by ClientLogin to send a POST request to log the
client out.
*/
func ClientLogout(client *http.Client) {
	// ClientLogout's code is exactly the same as ClientGetMainPage, except
	// a POST request is sent instead of GET.
	logger.Println("Logging out")

	response, err := client.PostForm("http://fakebank.com/logout", nil)
	if err != nil {
		logger.Panic(err)
	} else {
		logger.Println("Successfully received logout response")
	}
	defer response.Body.Close()
	bodyBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		logger.Panic(err)
	}
	logger.Println("Logout Page Response:", string(bodyBytes))
}

/*
ClientKillMITM
Parameters: None
Returns: None

You can use this function to test if your MITM exits successfully as
defined by the spec, that is, when the client makes a GET request to /kill.
*/
func ClientKillMITM() {
	_, err := http.Post("http://fakebank.com/logout", "application/json", nil)
	if err == nil {
		// This line will print when you run the starter code with no MITM.
		logger.Println("Did The MITM Exit?")
	}
}

/*
main
Parameters: None
Returns: None

Uses the starter code's DNS server as a reference, then runs all the client
functions defined above in this file.
*/
func main() {
	// Override the default DNS server with our own.
	r := net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			// We need to set the DNS resolver to an invalid IP address
			// Otherwise there is a race condition where either the correct or spoofed
			// DNS resolver will respond with an ARP response first
			return d.DialContext(ctx, "udp", "10.38.8.2:53")
		},
	}
	dialer := net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver:  &r,
	}
	http.DefaultTransport.(*http.Transport).DialContext = dialer.DialContext

	// Setup the http client and give it a cookie jar.
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		logger.Fatal(err)
	}

	client := &http.Client{
		Jar: jar,
	}

	// And finally, the functions simulating client behavior.
	// There is an intentional 5-second delay between each action
	// the client performs in order to make it look like a real human,
	// instead of sending requests as fast as it can.
	// The 033 is there just to make the text colored in the terminal!
	fmt.Println("\033[35m==========    STAGE 1/4: Logging in...        ==========\033[0m")
	ClientLogin(client)
	time.Sleep(3000 * time.Millisecond)
	fmt.Println("\033[35m==========    STAGE 2/4: Visiting homepage...     ==========\033[0m")
	ClientGetMainPage(client)
	time.Sleep(3000 * time.Millisecond)
	fmt.Println("\033[35m==========    STAGE 3/4: Transferring funds...    ==========\033[0m")
	ClientTransfer(client)
	time.Sleep(3000 * time.Millisecond)
	fmt.Println("\033[35m==========    STAGE 4/4: Logging out...        ==========\033[0m")
	ClientLogout(client)
	return
}
