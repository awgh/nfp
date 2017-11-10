package nfp

import (
	"log"
	"net/http"

	"container/list"

	"github.com/google/gopacket"
)

var metrics NetMetrics

func init() {
	metrics.HTTPStreams = list.New()
	metrics.TLSClientHellos = list.New()
}

// NetMetrics - counts network things
type NetMetrics struct {
	UnusablePacket  uint64
	DNSPacket       uint64
	TCPPacket       uint64
	UDPPacket       uint64
	HTTPStreams     *list.List
	TLSClientHellos *list.List
}

// Print this struct
func (m NetMetrics) Print() {
	log.Println("Unusable Packets", m.UnusablePacket)
	log.Println("DNS Packets", m.DNSPacket)
	log.Println("TCP Packets", m.TCPPacket)
	log.Println("UDP Packets", m.UDPPacket)
	log.Println("TLS/SSL Sessions", m.TLSClientHellos.Len())
	log.Println("HTTP Sessions", m.HTTPStreams.Len())

	i := 0
	front := m.HTTPStreams.Front()
	for front.Next() != nil {
		//log.Println(front)
		front = front.Next()
		i++
	}
	log.Println(i)
}

type HTTPStreamRecord struct {
	Net, Transport gopacket.Flow
	Request        *http.Request
	Response       *http.Response
	Extra          []byte
}
