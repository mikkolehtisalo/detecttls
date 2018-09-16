package main

import (
	"flag"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/pkg/profile"
)

var config = Config{}

func fileSource() *gopacket.PacketSource {
	if handle, err := pcap.OpenOffline(config.Input.Filename); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packetSource.Lazy = true
		packetSource.NoCopy = true
		return packetSource
	}
}

func networkSource() *gopacket.PacketSource {
	if handle, err := pcap.OpenLive(config.Input.Interface, int32(config.Input.Snaplen), config.Input.Promiscuous, pcap.BlockForever); err != nil {
		panic(err)
		// libpcap's implementation seems to be slower
		//} else if err := handle.SetBPFFilter("tcp"); err != nil { // Limit capturing to TCP traffic at pcap
		//	panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packetSource.Lazy = true
		packetSource.NoCopy = true
		return packetSource
	}
}

func parsePackets(ps *gopacket.PacketSource) {
	for packetData := range ps.Packets() {
		// let's create a job with the payload
		work := Job{Packet: packetData}

		// Increment waitgroup
		WGPool.Add(1)

		// Push the work onto the queue.
		JobQueue <- work
	}
}

func main() {
	var configFile = flag.String("cfg", "config.json", "configuration file")
	flag.Parse()

	if *configFile == "" {
		flag.PrintDefaults()
		return
	}

	// Initialize configuration
	config.Initialize(*configFile)

	// Enable profiling?
	if config.Debug.ProfileCPU {
		defer profile.Start().Stop()
	}
	if config.Debug.ProfileMEM {
		defer profile.Start(profile.MemProfile).Stop()
	}

	// Initialize packet source
	var ps *gopacket.PacketSource
	switch config.Input.Source {
	case "file":
		ps = fileSource()
	case "network":
		ps = networkSource()
	default:
		panic("Unknown source, valid values: file, network!")
	}

	// Initialize work queue
	InitializeJobQueue(config.Performance.MaxWorkers, config.Performance.MaxWorkers)

	// Parse!
	parsePackets(ps)

	// Wait for the job queue to clear
	for len(JobQueue) > 0 {
		// Just wait
	}

	// Wait for the processing to finish
	WGPool.Wait()

	// Give 1 second for outgoing logging to finish
	time.Sleep(1 * time.Second)

}
