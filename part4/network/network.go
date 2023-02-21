/*
CS155 Project 3
Part 3. Monster-in-the-Middle Attack

network.go
This file contains utility functions that your MITM should call; refer to
the TODOs in mitm.go for more details. This package is imported for you in
mitm.go's skeleton code, and you can call the functions below in your MITM
like this: cs155.StealClientCookie(...)
*/

package cs155

import (
	"fmt"
	"net"
)

/*
	StealClientCookie: For grading purposes, please use this function when
	stealing cookies sent by the client.

	Parameters: name and value of the cookie to print
	Returns: None
*/
func StealClientCookie(name string, value string) {
	fmt.Println("MITM:   Intercepted Cookie Sent By Client")
	fmt.Println("        Name:  ", name)
	fmt.Println("        Value: ", value)
}

/*
	StealServerCookie: For grading purposes, please use this function when
	stealing cookies set by the server.

	Parameters: name and value of the cookie to print
	Returns: None
*/
func StealServerCookie(name string, value string) {
	fmt.Println("MITM:   Intercepted Cookie Set By Server")
	fmt.Println("        Name:  ", name)
	fmt.Println("        Value: ", value)
}

/*
	StealCredentials: For grading purposes, please use this function when
	stealing login credentials.

	Parameters: captured username and password
	Returns: None
*/
func StealCredentials(username string, password string) {
	fmt.Println("MITM:   Intercepted Credentials")
	fmt.Println("        Username: ", username)
	fmt.Println("        Password: ", password)
}

/*
	GetLocalIP: For grading purposes, please use this function to obtain your
	IP address, to use when pretending to be fakebank.com.

	Parameters: None
	Returns: your IP address and subnet mask, written in CIDR notation (e.g. 10.0.1.2/24)
*/
func GetLocalIP() string {
	inter, _ := net.InterfaceByName("eth0")
	adList, _ := inter.Addrs()
	return adList[0].String()
}

/*
	GetLocalIP: For grading purposes, please use this function to obtain the
	true address of fakebank.com.

	Parameters: None
	Returns: the plain IPv4 address of the real fakebank.com (e.g. 10.0.1.3)
*/
func GetBankIP() string {
	return "10.38.8.3"
}

func GetLocalMAC() net.HardwareAddr {
	inter, _ := net.InterfaceByName("eth0")
	return inter.HardwareAddr
}
