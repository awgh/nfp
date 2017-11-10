package nfp

import (
	"bufio"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/bradleyfalzon/tlsx"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// HTTPStreamFactory implements tcpassembly.StreamFactory
type HTTPStreamFactory struct{}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

// New - make a new instance of an httpStream
func (h *HTTPStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go hstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

// IsHTTP Returns 0 for not HTTP, 1 for HTTP Request, and 2 for HTTP Response
func IsHTTP(prefix []byte) int {
	stb := string(prefix)
	if stb[:4] == "HTTP" {
		return 2 // response found
	}
	token := strings.Split(stb, " ")[0]
	verbs := []string{"GET", "OPTIONS", "POST", "TRACE", "TRACK",
		"PUT", "PATCH", "DELETE", "CONNECT", "HEAD"}
	for _, b := range verbs {
		if b == token {
			return 1 //request found
		}
	}
	return 0 // dunno
}

func (h *httpStream) run() {

	var record HTTPStreamRecord
	buf := bufio.NewReader(&h.r)

	for {
		tb, err := buf.Peek(10)
		if err != nil {
			if err != io.EOF {
				log.Println(err.Error())
			}
			break
		}
		rType := IsHTTP(tb)
		if rType == 1 {
			req, err := http.ReadRequest(buf)
			if err == io.EOF {
				break
			} else {
				b, _ := httputil.DumpRequest(req, true)
				record.Dump = append(record.Dump, b...)
				record.Net = h.net
				record.Transport = h.transport
				metrics.HTTPStreams.PushBack(record)
			}
		} else if rType == 2 {
			resp, err := http.ReadResponse(buf, nil)
			if err == io.EOF {
				break
			} else {
				b, _ := httputil.DumpResponse(resp, true)
				record.Dump = append(record.Dump, b...)
				record.Net = h.net
				record.Transport = h.transport
				metrics.HTTPStreams.PushBack(record)
			}
		} else {
			b, err := ioutil.ReadAll(buf)
			if err != nil {
				log.Println(err.Error())
			} else {
				var hello = tlsx.ClientHello{}
				if err := hello.Unmarshall(b); err != nil && hello.HandshakeType == 1 {
					metrics.TLSClientHellos.PushBack(hello)
				}
				break
			}
		}
	}
}
