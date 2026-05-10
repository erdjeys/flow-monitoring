// Package attacks provides traffic attack generators for network security testing.
package attacks

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"

	"github.com/flowmonitor/generator/flowexp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// zombieIPs is a fixed pool of spoofed external attacker IPs for SYN floods.
var zombieIPs = func() []net.IP {
	ips := make([]net.IP, 16)
	for i := range ips {
		ips[i] = net.IPv4(185, 220, 101, byte(i+1))
	}
	return ips
}()

// SYNFlood exports SYN flood flow records to the collector.
// Raw pcap injection is attempted for wire-level realism but is optional.
func SYNFlood(iface, dst, src string, dstPort uint16, duration time.Duration, exp *flowexp.Exporter) {
	dstIP := net.ParseIP(dst).To4()
	deadline := time.Now().Add(duration)

	handle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Printf("synflood pcap unavailable (flow export continues): %v", err)
		handle = nil
	} else {
		defer handle.Close()
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	sent := 0
	for time.Now().Before(deadline) {
		if handle != nil {
			if pkt, err := craftSYN(dst, dstPort); err == nil {
				if err := handle.WritePacketData(pkt); err != nil {
					log.Printf("synflood pcap write error (continuing): %v", err)
					handle.Close()
					handle = nil
				}
			}
		}
		sent++

		select {
		case <-ticker.C:
			batch := make([]flowexp.Record, 30)
			for i := range batch {
				batch[i] = flowexp.Record{
					SrcIP:    zombieIPs[(sent+i)%len(zombieIPs)],
					DstIP:    dstIP,
					DstPort:  dstPort,
					SrcPort:  uint16(1024 + rand.Intn(60000)),
					Protocol: 6,
					TCPFlags: 0x02,
					Packets:  1,
					Bytes:    60,
				}
			}
			exp.Send(batch)
		default:
		}

		time.Sleep(100 * time.Microsecond)
	}
	log.Printf("SYN flood complete: %d iterations → %s:%d", sent, dst, dstPort)
}

func craftSYN(dstIP string, dstPort uint16) ([]byte, error) {
	var srcArr [4]byte
	binary.BigEndian.PutUint32(srcArr[:], rand.Uint32())

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IP(srcArr[:]),
		DstIP:    net.ParseIP(dstIP).To4(),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(1024 + rand.Intn(60000)),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
		Window:  65535,
		Seq:     rand.Uint32(),
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// LateralMovement simulates a compromised host (target) probing all internal
// hosts repeatedly for the given duration (probe every 5 s).
func LateralMovement(target string, duration time.Duration, exp *flowexp.Exporter) {
	srcIP := net.ParseIP(target).To4()
	if srcIP == nil {
		srcIP = net.ParseIP("10.0.1.22").To4() // fallback: WS-Bravo
	}

	hosts := []struct {
		ip   net.IP
		port uint16
	}{
		{net.ParseIP("10.0.1.10").To4(), 8080},  // server
		{net.ParseIP("10.0.1.254").To4(), 8080}, // router (servers-net)
		{net.ParseIP("10.0.1.2").To4(), 8080},   // switch-servers
		{net.ParseIP("10.0.2.30").To4(), 9000},  // field sensor
		{net.ParseIP("10.0.2.2").To4(), 8080},   // switch-sensors
		{net.ParseIP("10.0.2.254").To4(), 8080}, // router (sensors-net)
		{net.ParseIP("10.0.3.20").To4(), 8080},  // agent
		{net.ParseIP("10.0.3.50").To4(), 2055},  // collector
		{net.ParseIP("10.0.3.254").To4(), 8080}, // router (mgmt-net)
	}

	deadline := time.Now().Add(duration)
	for round := 1; time.Now().Before(deadline); round++ {
		batch := make([]flowexp.Record, len(hosts))
		for i, h := range hosts {
			batch[i] = flowexp.Record{
				SrcIP: srcIP, DstIP: h.ip,
				SrcPort: uint16(40000 + rand.Intn(10000)), DstPort: h.port,
				Protocol: 6, TCPFlags: 0x02, Packets: 1, Bytes: 60,
			}
		}
		exp.Send(batch)
		log.Printf("Lateral movement round %d: %d hosts probed from %s", round, len(hosts), srcIP)
		time.Sleep(5 * time.Second)
	}
}

// PortScan performs a TCP connect scan against target on ports [startPort, endPort].
func PortScan(target string, startPort, endPort int, exp *flowexp.Exporter) {
	dstIP := net.ParseIP(target).To4()
	srcIP := net.ParseIP("10.0.1.40").To4() // generator

	open := 0
	batch := make([]flowexp.Record, 0, 30)

	for port := startPort; port <= endPort; port++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), 200*time.Millisecond)
		flags := uint8(0x06)
		if err == nil {
			conn.Close()
			open++
			flags = 0x12
		}

		batch = append(batch, flowexp.Record{
			SrcIP:    srcIP,
			DstIP:    dstIP,
			SrcPort:  uint16(40000 + rand.Intn(10000)),
			DstPort:  uint16(port),
			Protocol: 6,
			TCPFlags: flags,
			Packets:  1,
			Bytes:    60,
		})

		if len(batch) == 30 {
			exp.Send(batch)
			batch = batch[:0]
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(batch) > 0 {
		exp.Send(batch)
	}
	log.Printf("port scan %s:%d-%d complete, %d open", target, startPort, endPort, open)
}

// UDPFlood sends high-rate UDP datagrams and exports matching flow records.
func UDPFlood(dst string, dstPort int, duration time.Duration, exp *flowexp.Exporter) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", dst, dstPort))
	if err != nil {
		log.Printf("udpflood resolve: %v", err)
		return
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Printf("udpflood dial: %v", err)
		return
	}
	defer conn.Close()

	dstIP := net.ParseIP(dst).To4()
	srcIP := net.ParseIP("10.0.1.40").To4()
	payload := make([]byte, 512)
	deadline := time.Now().Add(duration)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	sent := 0
	for time.Now().Before(deadline) {
		conn.Write(payload)
		sent++

		select {
		case <-ticker.C:
			exp.Send([]flowexp.Record{{
				SrcIP:    srcIP,
				DstIP:    dstIP,
				SrcPort:  uint16(30000 + rand.Intn(10000)),
				DstPort:  uint16(dstPort),
				Protocol: 17,
				Packets:  2000,
				Bytes:    uint32(2000 * len(payload)),
			}})
		default:
		}

		time.Sleep(50 * time.Microsecond)
	}
	log.Printf("UDP flood complete: %d packets → %s:%d", sent, dst, dstPort)
}

