package nfp

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"time"
)

// Analyze - run packet analysis on pcap handle for given duration
func Analyze(pcap *pcap.Handle, seconds uint64) {

	var secondsRunning uint64
	var metrics NetMetrics

	// Set up assembly
	streamFactory := &HTTPStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	packetSource := gopacket.NewPacketSource(pcap, pcap.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Second)

Loop:
	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				break Loop
			}
			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
				metrics.UnusablePacket++
				continue
			}
			if packet.ApplicationLayer() != nil && packet.ApplicationLayer().LayerType() == layers.LayerTypeDNS {
				metrics.DNSPacket++

				//dns := packet.ApplicationLayer().(*layers.DNS)
				//log.Println(dns)
				// dns

			} else if packet.TransportLayer().LayerType() == layers.LayerTypeTCP {
				metrics.TCPPacket++
				tcp := packet.TransportLayer().(*layers.TCP)
				assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
			} else if packet.TransportLayer().LayerType() == layers.LayerTypeUDP {
				metrics.UDPPacket++
				//udp := packet.TransportLayer().(*layers.UDP)
				//log.Println(udp)
				// udp
			}

		case <-ticker:
			secondsRunning++

			if seconds > 0 && secondsRunning >= seconds {
				break Loop
			}

			if secondsRunning%60 == 0 {
				// Every minute, flush connections that haven't seen activity in the past 2 minutes.
				assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
			}
		}
	}
	metrics.Print()
}
