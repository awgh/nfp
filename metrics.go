package nfp

import (
	"fmt"
	"log"
	"strconv"

	"container/list"

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

	DNSRequests     map[string]int
	HTTPStreams     *list.List
	TLSClientHellos *list.List
}

// Print this struct
func (m NetMetrics) Print() {
	log.Println("Unusable Packets", m.UnusablePacket)
	log.Println("DNS Packets", m.DNSPacket)

	var db []string
	for k, v := range m.DNSRequests {
		db = append(db, k+"|"+strconv.Itoa(v))
	}
	fmt.Println(columnize.SimpleFormat(db))

	log.Println("TCP Packets", m.TCPPacket)
	log.Println("UDP Packets", m.UDPPacket)
	log.Println("TLS/SSL Sessions", m.TLSClientHellos.Len())
	hi := m.TLSClientHellos.Front()
	for hi.Next() != nil {
		h := hi.Value.(tlsx.ClientHello)
		fmt.Println(h.HandshakeVersion, h.SNI, h.CipherSuites)
		hi = hi.Next()
	}

	log.Println("HTTP Sessions", m.HTTPStreams.Len())
	front := m.HTTPStreams.Front()
	sbi := 0
	sb := make([]string, m.HTTPStreams.Len())
	for front.Next() != nil {
		s := front.Value.(HTTPStreamRecord)
		sb[sbi] = s.Net.Src().String() + "|" + s.Transport.Src().String() + "|" +
			s.Net.Dst().String() + "|" + s.Transport.Dst().String()
		sbi++
		//if s.Dump != nil {
		//log.Println("DUMP\n", string(s.Dump), "\n")
		//}
		front = front.Next()
	}
	fmt.Println(columnize.SimpleFormat(sb))
}

type HTTPStreamRecord struct {
	Net, Transport gopacket.Flow
	Dump           []byte
}
