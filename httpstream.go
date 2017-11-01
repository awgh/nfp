package nfp

import (
	"bufio"
	"github.com/bradleyfalzon/tlsx"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
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
	rType := IsHTTP(tb)
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
