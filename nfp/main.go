package main

import (
	"flag"
	"log"
	"time"

	"github.com/awgh/nfp"
	"github.com/google/gopacket/pcap"
)

// Flags
var iface = flag.String("i", "eth0", "Interface to read packets from")
var seconds = flag.Uint64("s", 60, "Time to listen for packets, in seconds")
var fname = flag.String("f", "", "Filename to read from, overrides -i and -s")
var snaplen = 65536
var promisc = true

func main() {

	flag.Parse()

	var handle *pcap.Handle
	var err error
	var metrics nfp.NetMetrics

	if *fname != "" {
		if handle, err = pcap.OpenOffline(*fname); err != nil {
			log.Fatal("PCAP OpenOffline error:", err)
		}
		metrics = nfp.Analyze(handle, 0)
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

		metrics = nfp.Analyze(handle, *seconds)
	}

	metrics.Print()
}
