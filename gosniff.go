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
	snapshot_len int32  = 65535
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = -1 * time.Second
	handle       *pcap.Handle
)

func main() {
	//Arguments
	//os.Args = []string{"gosniff", "--interface", "eth0"}

	app := &cli.App{
		Name:  "gosniff",
		Usage: "gosniff --interface eth0",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "interface, i", Value: "eth0", Usage: "the interface to use", Destination: &device},
		},
		Action: func(c *cli.Context) error {
			fmt.Printf("Interface %v\n", c.String("interface"))
			sniff(device)
			return nil
		},
		UsageText: "app [first_arg] [second_arg]",
		Authors:   []*cli.Author{{Name: "Fernandez, Chris", Email: "cfernandez@protonmail.ch"}},
	}

	app.Run(os.Args)
}

func sniff(device string) string {

	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter
	err = handle.SetBPFFilter("tcp and port 80")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Capturing TCP port 80 packets.")

	// Process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println(packet)
	}
	return device
}
