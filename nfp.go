package main

import (
	"bufio"
	"flag"
	"github.com/bradleyfalzon/tlsx"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

// Flags
var iface = flag.String("i", "eth0", "Interface to read packets from")
var fname = flag.String("f", "", "Filename to read from, overrides -i")
var snaplen = 65536
var promisc = true

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct{}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go hstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

// isHTTP Returns 0 for not HTTP, 1 for HTTP Request, and 2 for HTTP Response
func isHTTP(prefix []byte) int {
	//log.Println("isHttp", len(prefix), prefix, string(prefix))
	stb := string(prefix)
	if stb[:4] == "HTTP" {
		return 2 // response found
	}
	token := strings.Split(stb, " ")[0]
	switch token {
	case "GET":
		fallthrough
	case "OPTIONS":
		fallthrough
	case "POST":
		fallthrough
	case "TRACE":
		fallthrough
	case "TRACK":
		fallthrough
	case "PUT":
		fallthrough
	case "PATCH":
		fallthrough
	case "DELETE":
		fallthrough
	case "CONNECT":
		fallthrough
	case "HEAD":
		return 1 // request found
	}
	return 0 // dunno
}

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	tb, err := buf.Peek(10)
	if err != nil {
		if err != io.EOF {
			log.Println(err.Error())
		}
		return
	}
	rType := isHTTP(tb)
	if rType == 1 {
		for {
			r, err := http.ReadRequest(buf)
			if err == io.EOF {
				return
			} else if err != nil {
				//log.Println("Error reading stream", h.net, h.transport, ":", err)
			} else {
				bodyBytes := tcpreader.DiscardBytesToEOF(r.Body)
				r.Body.Close()
				log.Println("Received request from stream", h.net, h.transport, ":", r, "with", bodyBytes, "bytes in request body")
			}
		}
	} else if rType == 2 {
		for {
			r, err := http.ReadResponse(buf, nil)
			if err == io.EOF {
				return
			} else if err != nil {
				//log.Println("Error reading stream", h.net, h.transport, ":", err)
			} else {
				bodyBytes := tcpreader.DiscardBytesToEOF(r.Body)
				r.Body.Close()
				log.Println("Received response from stream", h.net, h.transport, ":", r, "with", bodyBytes, "bytes in response body")
			}
		}
	} else {
		b, err := ioutil.ReadAll(buf)
		if err != nil {
			log.Println(err.Error())
		} else {
			var hello = tlsx.ClientHello{}
			err := hello.Unmarshall(b)
			switch err {
			case nil:
			case tlsx.ErrHandshakeWrongType:
				return
			}
			//log.Println(hello)
			//ssl
		}
	}
}

func main() {

	flag.Parse()

	var handle *pcap.Handle
	var err error
	if *fname != "" {
		if handle, err = pcap.OpenOffline(*fname); err != nil {
			log.Fatal("PCAP OpenOffline error:", err)
		}
	} else {
		inactive, err := pcap.NewInactiveHandle(*iface)
		if err != nil {
			log.Fatalf("could not create: %v", err)
		}
		defer inactive.CleanUp()
		if err = inactive.SetSnapLen(snaplen); err != nil {
			log.Fatalf("could not set snap length: %v", err)
		} else if err = inactive.SetPromisc(promisc); err != nil {
			log.Fatalf("could not set promisc mode: %v", err)
		} else if err = inactive.SetTimeout(time.Second); err != nil {
			log.Fatalf("could not set timeout: %v", err)
		}
		if handle, err = inactive.Activate(); err != nil {
			log.Fatal("PCAP Activate error:", err)
		}
		defer handle.Close()
	}

	// Set up assembly
	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)
	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				return
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
				//log.Println("Unusable packet")
				continue
			}
			if packet.ApplicationLayer() != nil && packet.ApplicationLayer().LayerType() == layers.LayerTypeDNS {
				//dns := packet.ApplicationLayer().(*layers.DNS)
				//log.Println(dns)
				// dns

			} else if packet.TransportLayer().LayerType() == layers.LayerTypeTCP {
				tcp := packet.TransportLayer().(*layers.TCP)
				assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
			} else if packet.TransportLayer().LayerType() == layers.LayerTypeUDP {
				//udp := packet.TransportLayer().(*layers.UDP)
				//log.Println(udp)
				// udp
			}

		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}
