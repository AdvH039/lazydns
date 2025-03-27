package main

import (
	"fmt"
	"log"
	"net"
)

// Function to construct a DNS query for "fake.example.com"
func buildDNSQuery() []byte {
	// Transaction ID (2 bytes) - Arbitrary ID (e.g., 0x1234)
	txID := []byte{0x12, 0x34}

	// Flags (2 bytes) - Standard query (0x0100)
	flags := []byte{0x01, 0x00}

	// Questions (2 bytes) - Asking 1 question
	qdCount := []byte{0x00, 0x01}

	// Answer RRs, Authority RRs, Additional RRs (all 2 bytes, set to 0)
	other := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	// Query Name (fake.example.com encoded as 3www6google3com0)
	qname := []byte{
		0x04, 'f', 'a', 'k', 'e', // "fake"
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // "example"
		0x03, 'c', 'o', 'm', // "com"
		0x00, // End of domain
	}

	// Query Type (A record - 0x0001)
	qtype := []byte{0x00, 0x01}

	// Query Class (IN - Internet - 0x0001)
	qclass := []byte{0x00, 0x01}

	// Construct full DNS packet
	dnsQuery := append(txID, flags...)
	dnsQuery = append(dnsQuery, qdCount...)
	dnsQuery = append(dnsQuery, other...)
	dnsQuery = append(dnsQuery, qname...)
	dnsQuery = append(dnsQuery, qtype...)
	dnsQuery = append(dnsQuery, qclass...)

	return dnsQuery
}

func main() {
	// Address of the process listening on localhost:9443
	serverAddr := "127.0.0.1:9443"

	// Resolve UDP address
	addr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		log.Fatalf("Failed to resolve address: %v", err)
	}

	// Create UDP connection
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// Build DNS Query
	dnsQuery := buildDNSQuery()

	// Send DNS Query
	_, err = conn.Write(dnsQuery)
	if err != nil {
		log.Fatalf("Failed to send DNS query: %v", err)
	}

	fmt.Println("Sent DNS query for fake.example.com to", serverAddr)

	// Read Response (Optional)
	buffer := make([]byte, 512)
	n, _, err := conn.ReadFrom(buffer)
	if err != nil {
		log.Fatalf("Failed to read response: %v", err)
	}

	fmt.Println("Received response:", buffer[:n])
}
