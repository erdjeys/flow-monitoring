package capture

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	snapLen     = 65535
	promiscuous = true
	pcapTimeout = 30 * time.Millisecond
	chanBuf     = 10000
)

// Capture wraps a pcap handle and exposes a packet channel.
type Capture struct {
	handle  *pcap.Handle
	packets chan gopacket.Packet
}

func New(iface string) (*Capture, error) {
	handle, err := pcap.OpenLive(iface, snapLen, promiscuous, pcapTimeout)
	if err != nil {
		return nil, err
	}

	c := &Capture{
		handle:  handle,
		packets: make(chan gopacket.Packet, chanBuf),
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	src.NoCopy = true

	go func() {
		defer close(c.packets)
		for pkt := range src.Packets() {
			c.packets <- pkt
		}
	}()

	return c, nil
}

func (c *Capture) Packets() <-chan gopacket.Packet { return c.packets }

func (c *Capture) Close() { c.handle.Close() }
