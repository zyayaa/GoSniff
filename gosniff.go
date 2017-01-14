package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"gopkg.in/urfave/cli.v2"
)

var (
	device       string = "wlp4s0"
	suck         string = "tcp and port 443"
	snapshot_len int32  = 65535
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = -1 * time.Second
	handle       *pcap.Handle
)

func main() {

	app := &cli.App{
		Name:    "gosniff",
		Usage:   "gosniff --interface eth0 --sniff \"tcp and port 80\"",
		Version: "0.0.1",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "interface, i", Value: "eth0", Usage: "the interface to use", Destination: &device},
			&cli.StringFlag{Name: "sniff, s", Value: "tcp and port 443", Usage: "the BPF syntax parameters to sniff on", Destination: &suck},
		},
		Action: func(c *cli.Context) error {
			fmt.Printf("Capturing on Interface %v\n with BPF syntax: %v\n", c.String("interface"), c.String("suck"))
			sniff(device, suck)
			return nil
		},

		UsageText: "app [first_arg] [second_arg]",
		Authors:   []*cli.Author{{Name: "Fernandez,Chris ReK2", Email: "cfernandez@protonmail.ch"}},
	}

	app.Run(os.Args)
}

func sniff(device string, suck string) string {

	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter
	err = handle.SetBPFFilter(suck)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Capturing %v", suck)

	// Process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println(packet)
	}
	return device
}
