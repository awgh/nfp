package nfp

import (
	"container/list"
	"fmt"
	"strconv"

	"github.com/bradleyfalzon/tlsx"
	"github.com/google/gopacket"
	"github.com/ryanuber/columnize"
)

var metrics NetMetrics

func init() {
	metrics.HTTPStreams = list.New()
	metrics.TLSClientHellos = list.New()
	metrics.DNSRequests = make(map[string]int)
}

// NetMetrics - counts network things
type NetMetrics struct {
	UnusablePacket uint64
	DNSPacket      uint64
	TCPPacket      uint64
	UDPPacket      uint64
	IPSecAHPacket  uint64
	IPSecESPPacket uint64

	DNSRequests     map[string]int
	HTTPStreams     *list.List
	TLSClientHellos *list.List
}

// Print this struct
func (m NetMetrics) Print() {

	fmt.Println("---SUMMARY---")
	fmt.Println("Unusable Packets", m.UnusablePacket)
	fmt.Println("DNS Packets", m.DNSPacket)
	fmt.Println("TCP Packets", m.TCPPacket)
	fmt.Println("UDP Packets", m.UDPPacket)
	fmt.Println("TLS/SSL Sessions", m.TLSClientHellos.Len())
	fmt.Println("HTTP Sessions", m.HTTPStreams.Len())
	fmt.Println("IPSec AH Packets", m.IPSecAHPacket)
	fmt.Println("IPSec ESP Packets", m.IPSecESPPacket)

	var db []string
	for k, v := range m.DNSRequests {
		db = append(db, k+"|"+strconv.Itoa(v))
	}
	fmt.Println("\n---DNS REQUESTS---\n" + columnize.SimpleFormat(db))

	fmt.Println("\n---TLS SESSIONS---")
	hi := m.TLSClientHellos.Front()
	for hi != nil && hi.Next() != nil {
		h := hi.Value.(tlsx.ClientHello)
		fmt.Println("\n", h.HandshakeVersion, h.SNI)
		var cb []string
		var ci int
		for ci < len(h.CipherSuites) {
			row := h.CipherSuites[ci].String()
			for i := 0; i < 4; i++ {
				ci++
				if ci < len(h.CipherSuites) {
					row += "|" + h.CipherSuites[ci].String()
				} else {
					break
				}
			}
			cb = append(cb, row)
		}
		//fmt.Println(columnize.SimpleFormat(cb))
		hi = hi.Next()
	}

	front := m.HTTPStreams.Front()
	sbi := 0
	sb := make([]string, m.HTTPStreams.Len())
	for front != nil && front.Next() != nil {
		s := front.Value.(HTTPStreamRecord)
		sb[sbi] = s.Net.Src().String() + "|" + s.Transport.Src().String() + "|" +
			s.Net.Dst().String() + "|" + s.Transport.Dst().String()
		sbi++
		//if s.Dump != nil {
		//log.Println("DUMP\n", string(s.Dump), "\n")
		//}
		front = front.Next()
	}
	fmt.Println("\n---HTTP SESSIONS---\n" + columnize.SimpleFormat(sb))
}

type HTTPStreamRecord struct {
	Net, Transport gopacket.Flow
	Dump           []byte
}
