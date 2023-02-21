/*
CS155 Project 3
Part 4. Monster-in-the-Middle Attack

dns_server.go
When compiled, this code will simulate the behavior of an innocent
DNS server. That is, it will listen for incoming questions and respond
truthfully to the real IP address that corresponds to a domain name.
*/

package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
)

// A map is analogous to a Python dictionary. map[string]string
// just specifies that both the keys and values are strings.
var records = map[string]string{
	"fakebank.com": "10.38.8.3",
	"test.com": "176.32.103.205",
}

/*
main
Parameters: None
Returns: None

Initializes the DNS server's cache, and then listens on UDP port 53
until stopped with Ctrl+C. On an incoming request, serveDNS is called.
*/
func main() {
	// ListenUDP returns a connection object to keep state, and an error
	// variable. Listening should be error-free.
	connection, err := net.ListenUDP("udp", &net.UDPAddr{Port: 53})
	if err != nil {
		panic(err)
	}
	// Loop indefinitely. Go has no while loop! A for loop with no condition
	// corresponds to "while true".
	for {
		// make() here creates a 1024-byte array to serve as a buffer.
		buffer := make([]byte, 1024)
		if buffer == nil {
			panic("unable to make buffer")
		}
		// ReadFrom returns <# of bytes read>, <client's address>, <error>
		// but the client address is the only value of interest.
		_, clientAddress, err := connection.ReadFrom(buffer)
		if err != nil {
			panic(err)
		}
		// buffer contains a packet, but in raw bytes. NewPacket converts it
		// into a data structure which facilitates handling. The incoming
		// traffic must be a DNS question, hence the second parameter.
		// Don't worry about gopacket.Default, which deals with how the library
		// copies and processes data.
		packet := gopacket.NewPacket(buffer, layers.LayerTypeDNS, gopacket.Default)
		// Getting the data of the DNS layer is a two-step process in Go.
		// First, select a layer in the Packet object, and then type-switch
		// it to the correct interface.
		dnsPacket := packet.Layer(layers.LayerTypeDNS)
		dnsData, _ := dnsPacket.(*layers.DNS)
		serveDNS(connection, clientAddress, dnsData)
	}
}

/*
serveDNS
Parameters: connection - a pointer to a UDP connection object, which keeps
stateful data; clientAddress - the IP address to reply to; request - the
DNS layer data from the client, containing the question.
Returns: None

Makes a reply to the client's DNS question, but does not send it unless the
last line is commented out. Even though (by default) the DNS server does not
reply, it still needs to run in the background; otherwise, the client will
throw an error that it could not open a connection to the DNS server.
*/
func serveDNS(connection *net.UDPConn, clientAddress net.Addr, request *layers.DNS) {
	// Strictly, this copies a pointer - so we're appending data to the client's
	// question, and throwing it back. The alias is just for clarity.
	replyMsg := request
	// dnsAnswer is a data structure that we will add on to the DNS data.
	// Hint: this part may be helpful in your MITM when you have to spoof
	// a DNS answer!
	var dnsAnswer layers.DNSResourceRecord
	// Use the map declared earlier to find the IP corresponding to the URL.
	ipString, ok := records[string(request.Questions[0].Name)]
	if !ok {
		panic("Error: Answer to DNS question not found.")
	}
	// This line is just to convert the stringified IP address into an
	// IP object, which gopacket understands.
	ipAddress, _, _ := net.ParseCIDR(ipString + "/24")
	// Now we can populate the data structure. Type A indicates that
	// the question is a domain name, and the answer is an IPv4 address.
	dnsAnswer.Type = layers.DNSTypeA
	dnsAnswer.IP = ipAddress
	// This just copies the domain name, but as a byte array.
	dnsAnswer.Name = request.Questions[0].Name
	// IN stands for internet - it is the namespace of this DNS request/reply.
	// DNS can be used for protocols other than internet, but that's
	// obviously beyond the scope of this project.
	dnsAnswer.Class = layers.DNSClassIN
	// QR = false indicates the DNS packet is a question; true indicates answer.
	replyMsg.QR = true
	// The number of answers: just one.
	replyMsg.ANCount = 1
	// This corresponds to a "200 OK" in HTTP; everything is good.
	replyMsg.ResponseCode = layers.DNSResponseCodeNoErr
	// Finally, augment dnsAnswer to the DNS data.
	replyMsg.Answers = append(replyMsg.Answers, dnsAnswer)
	// This last part deals with converting the DNS data structure to raw bytes.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := replyMsg.SerializeTo(buf, opts)
	if err != nil {
		panic(err)
	}

	// Uncomment the line below to make the server respond.
	// You will need to do this if you want to verify your starter code
	// and setup are working, but disable this when your MITM is up.
	//connection.WriteTo(buf.Bytes(), clientAddress)
}
