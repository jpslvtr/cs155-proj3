/*
 * Stanford CS155 Project 3
 * Part 3. Anomaly Detection
 *
 * detector.go
 *
 * When completed (by you!) and compiled, this program will:
 *
 *  - Open a .pcap file supplied as a command-line argument, and analyze the TCP,
 *    IP, Ethernet, and ARP layers
 *
 *  - Print the IP addresses that: 1) sent more than 3 times as many SYN packets
 *    as the number of SYN+ACK packets they received, and 2) sent more than 5 SYN
 *    packets in total
 *
 *  - Print the MAC addresses that send more than 5 unsolicited ARP replies
 *
 * This starter code is provided solely for convenience, to help build
 * familiarity with Go. You are free to use as much or as little of this code
 * as you see fit.
 */

package main

import (
	// You may use any packages in gopacket or the Go standard library,
	// but we think these should be sufficient. You MAY NOT use any
	// third party libraries. The autograder will not build with these.

	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	if len(os.Args) != 2 {
		panic("Invalid command-line arguments")
	}
	pcapFile := os.Args[1]

	// Attempt to open file
	if handle, err := pcap.OpenOffline(pcapFile); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		// Here, we provide some data structures that you may find useful.
		// Maps in Go are very similar to Python's dictionaries.
		// The Go syntax to declare an empty map is map[KEY_TYPE]VALUE_TYPE{}.
		// Key = IP address, value = array of 2 ints representing [syn, synack] counts
		addresses := map[string][2]int{}
		// Key = IP address, value = map (this is a nested map!) whose key = MAC address,
		// and value = int. You can use this to track the number of requests and replies
		// for pairs of (IP address, MAC address).
		arpRequests := map[string]map[string]int{}
		// Key = MAC address, value = int. Use this to store offending MAC addresses,
		// as well as how many times each one sent an unsolicited reply.
		arpMac := map[string]int{}

		// Loop through packets in file
		// Recommendation: Encapsulate packet handling and/or output in separate functions!
		for packet := range packetSource.Packets() {
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			etherLayer := packet.Layer(layers.LayerTypeEthernet)
			arpLayer := packet.Layer(layers.LayerTypeARP)

			if tcpLayer != nil && ipLayer != nil && etherLayer != nil {

				/*
				   TODO: obtain the source and destination IP addresses using
				   ipLayer, and the TCP flags using tcpLayer. Update the variable
				   addresses accordingly. You will want to have an if-statement
				   that branches on SYN vs. SYN/ACK. Note than a SYN packet has
				   the SYN flag set to true, AND the ACK flag set to false!
				*/

			} else if arpLayer != nil {

				/*
				   TODO: Use the arp variable to get (IP address, MAC address)
				   pairs for the source and destination. Fill in the if-else if
				   statement below as well. arp.Operation has a value of 1 if the
				   ARP packet is a request, and 2 if it is a reply. Update the
				   variable arpRequests accordingly. If you spot an unsolicited
				   reply, update arpMac.
				*/

				arp, _ := arpLayer.(*layers.ARP)
				// Parse arp to get additional info
				if arp.Operation == 1 {
					// Write code for handling an ARP request
				} else if arp.Operation == 2 {
					// Write code for handling an ARP reply
				}
			}
		}
		fmt.Println("Unauthorized SYN scanners:")
		for ip, addr := range addresses {
			// TODO: Print syn scanners
		}

		fmt.Println("Unauthorized ARP spoofers:")
		for mac, count := range arpMac {
			// TODO: Print arp spoofers
		}
	}
}

/*
Hints and Links to Documentation:

To access the member variables of each Layer,
you will need to type-cast it to the correct struct. For example,
tcpData, _ := tcpLayer.(*layers.TCP)

Here are some links to useful pages of Gopacket documentation, or
source code of layer objects in Gopacket. The names of the
struct member variables are self-explanatory.

https://github.com/google/gopacket/blob/master/layers/tcp.go Lines 20-35
https://github.com/google/gopacket/blob/master/layers/ip4.go Lines 43-59
https://github.com/google/gopacket/blob/master/layers/arp.go Lines 18-36
In arp.go, HwAddress is the MAC address, and
ProtAddress is the IP address in this case. Both are []byte variables.

https://golang.org/pkg/net/#IP and HardwareAddr (scroll up!) are
new type definitions for a []byte. Read more about type definitions at:
https://stackoverflow.com/questions/49402138/what-is-the-meaning-of-this-type-declaration
Hint: you can type-cast a []byte to a net.IP or net.HardwareAddr object.

https://golang.org/pkg/net/#IP.String - How to stringify IP addresses
https://golang.org/pkg/net/#HardwareAddr.String - How to stringify MAC addresses
*/
