package nfp

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

// Analyze - run packet analysis on pcap handle for given duration
func Analyze(pcap *pcap.Handle, seconds uint64) NetMetrics {

	var secondsRunning uint64

	// Set up assembly
	streamFactory := &HTTPStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	packetSource := gopacket.NewPacketSource(pcap, pcap.LinkType())
	packetSource.DecodeOptions.NoCopy = true // we promise not to alter slices (optimization)
	packetSource.DecodeOptions.Lazy = true   // lazy is evil; evil is good
	packets := packetSource.Packets()
	ticker := time.NewTicker(time.Second)

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
			if packet.ApplicationLayer() != nil &&
				packet.ApplicationLayer().LayerType() == layers.LayerTypeDNS {

				metrics.DNSPacket++
				dns := packet.ApplicationLayer().(*layers.DNS)
				for qi, _ := range dns.Questions {
					name := string(dns.Questions[qi].Name)
					v, ok := metrics.DNSRequests[name]
					if !ok {
						metrics.DNSRequests[name] = 1
					} else {
						metrics.DNSRequests[name] = v + 1
					}
				}

			} else if packet.TransportLayer().LayerType() == layers.LayerTypeTCP {
				metrics.TCPPacket++
				tcp := packet.TransportLayer().(*layers.TCP)
				assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(),
					tcp, packet.Metadata().Timestamp)

			} else if packet.TransportLayer().LayerType() == layers.LayerTypeUDP {
				metrics.UDPPacket++
				//udp := packet.TransportLayer().(*layers.UDP)
				//udp.

				//log.Println(udp)
				// udp

			}

		case <-ticker.C:
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

	return metrics
}
