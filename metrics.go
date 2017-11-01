package nfp

import (
	"log"
)

// NetMetrics - counts network things
type NetMetrics struct {
	UnusablePacket uint64
	DNSPacket      uint64
	TCPPacket      uint64
	UDPPacket      uint64
}

// Print this struct
func (m NetMetrics) Print() {
	log.Println("Unusable Packets", m.UnusablePacket)
	log.Println("DNS Packets", m.DNSPacket)
	log.Println("TCP Packets", m.TCPPacket)
	log.Println("UDP Packets", m.UDPPacket)
}
