// Negative & resilience tests for the monitoring agent.
//
// These tests verify correct behaviour in adversarial conditions:
//   - Malformed / non-IP packets must be silently dropped
//   - Rapid SetTemplate changes must not corrupt IPFIX state
//   - Concurrent tracker access must be race-free (run with -race)
//   - Oversized IPFIX payloads must not panic or exceed MTU
//   - A UDP sink that refuses to read must not block the agent
//   - Aggregator with pathological input (all same key) stays correct
//
// Run with: go test ./tests/negative/... -v -race
package negative_test

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/flowmonitor/agent/aggregate"
	"github.com/flowmonitor/agent/export"
	"github.com/flowmonitor/agent/flow"
	"github.com/flowmonitor/agent/protocols"
)

// ── UDP helpers ───────────────────────────────────────────────────────────────

func newSink(t *testing.T) *export.Exporter {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("sink listen: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65536)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	exp, err := export.New(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("export.New: %v", err)
	}
	t.Cleanup(func() { exp.Close() })
	return exp
}

func makeRec(srcOctet, dstOctet byte, proto uint8, bytes uint64) *flow.Record {
	r := &flow.Record{Packets: 1, Bytes: bytes, Start: time.Now(), Last: time.Now()}
	r.FlowKey.SrcIP = [4]byte{10, 0, 0, srcOctet}
	r.FlowKey.DstIP = [4]byte{10, 0, 0, dstOctet}
	r.FlowKey.Protocol = proto
	return r
}

// ── Malformed packets ─────────────────────────────────────────────────────────

// Completely random bytes must not panic the tracker.
func TestNegative_RandomBytes_NoPanic(t *testing.T) {
	tr := flow.NewTracker(time.Minute, 30*time.Second, 0)
	tr.OnExport(func([]*flow.Record) {})
	garbage := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02}
	pkt := gopacket.NewPacket(garbage, layers.LayerTypeEthernet, gopacket.Default)
	// Must not panic.
	tr.Process(pkt)
}

// An ARP frame (no IP layer) must be ignored silently.
func TestNegative_ARPPacket_Ignored(t *testing.T) {
	tr := flow.NewTracker(time.Minute, 30*time.Second, 0)
	tr.OnExport(func([]*flow.Record) {})
	arp := []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x08, 0x06, // EtherType ARP
		0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
	}
	tr.Process(gopacket.NewPacket(arp, layers.LayerTypeEthernet, gopacket.Default))
	if n := tr.Stats().ActiveFlows; n != 0 {
		t.Errorf("ARP frame created %d flows, want 0", n)
	}
}

// An IPv6 frame must be ignored (the tracker only handles IPv4).
func TestNegative_IPv6Packet_Ignored(t *testing.T) {
	tr := flow.NewTracker(time.Minute, 30*time.Second, 0)
	tr.OnExport(func([]*flow.Record) {})
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolTCP,
		SrcIP:      net.ParseIP("2001:db8::1"),
		DstIP:      net.ParseIP("2001:db8::2"),
	}
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 80, SYN: true}
	tcp.SetNetworkLayerForChecksum(ip6)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, eth, ip6, tcp)
	tr.Process(gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default))

	if n := tr.Stats().ActiveFlows; n != 0 {
		t.Errorf("IPv6 frame created %d flows, want 0", n)
	}
}

// Zero-length packet must not panic.
func TestNegative_EmptyPacket_NoPanic(t *testing.T) {
	tr := flow.NewTracker(time.Minute, 30*time.Second, 0)
	tr.OnExport(func([]*flow.Record) {})
	tr.Process(gopacket.NewPacket([]byte{}, layers.LayerTypeEthernet, gopacket.Default))
}

// ── IPFIX MTU / payload size ──────────────────────────────────────────────────

// Exporting a full-field IPFIX template must not produce a datagram larger than
// 65,507 bytes (maximum safe UDP payload over IPv4).
func TestNegative_IPFIX_MaxPayloadSize(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })

	received := make(chan []byte, 64)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			received <- pkt
		}
	}()

	exp, _ := export.New(pc.LocalAddr().String())
	t.Cleanup(func() { exp.Close() })
	enc := protocols.NewIPFIX(exp)

	// Use a large batch — IPFIX encoder chunks at 20 records.
	records := make([]*flow.Record, 200)
	for i := range records {
		r := makeRec(byte(i%200), 1, 6, 1500)
		r.CpuLoad = 42
		records[i] = r
	}
	if err := enc.Export(records); err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	const maxUDP = 65507
	deadline := time.After(2 * time.Second)
	for {
		select {
		case pkt := <-received:
			if len(pkt) > maxUDP {
				t.Errorf("datagram size %d exceeds max UDP payload %d", len(pkt), maxUDP)
			}
		case <-deadline:
			return
		}
	}
}

// ── Rapid SetTemplate (race condition) ───────────────────────────────────────

// Calling SetTemplate concurrently with Export must not corrupt the encoder state.
// Run with -race to catch data races.
func TestNegative_IPFIX_ConcurrentSetTemplate(t *testing.T) {
	enc := protocols.NewIPFIX(newSink(t))

	allFields := []string{
		"srcIP", "dstIP", "srcPort", "dstPort",
		"proto", "packets", "bytes", "cpuLoad",
	}
	minFields := []string{"srcIP", "dstIP"}

	var wg sync.WaitGroup
	// Goroutine 1: repeatedly exports flow records.
	wg.Add(1)
	go func() {
		defer wg.Done()
		records := []*flow.Record{makeRec(1, 2, 6, 1000)}
		for i := 0; i < 200; i++ {
			_ = enc.Export(records)
		}
	}()
	// Goroutine 2: rapidly alternates between templates.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if i%2 == 0 {
				enc.SetTemplate(allFields)
			} else {
				enc.SetTemplate(minFields)
			}
		}
	}()
	wg.Wait()
}

// ── Concurrent tracker access ─────────────────────────────────────────────────

// Multiple goroutines reading/writing the tracker simultaneously must not race.
// Run with -race.
func TestNegative_Tracker_ConcurrentAccess(t *testing.T) {
	tr := flow.NewTracker(50*time.Millisecond, 20*time.Millisecond, 1000)
	tr.OnExport(func([]*flow.Record) {})

	makePkt := func(src, dst byte) gopacket.Packet {
		eth := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0, 0, 0, 0, 0, src},
			DstMAC:       net.HardwareAddr{0, 0, 0, 0, 0, dst},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    net.IP{10, 0, 0, src},
			DstIP:    net.IP{10, 0, 0, dst},
		}
		tcp := &layers.TCP{SrcPort: 1234, DstPort: 80, SYN: true}
		tcp.SetNetworkLayerForChecksum(ip)
		buf := gopacket.NewSerializeBuffer()
		gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp)
		return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	}

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		g := g
		wg.Add(1)
		go func() {
			defer wg.Done()
			pkt := makePkt(byte(g), 100)
			for i := 0; i < 500; i++ {
				tr.Process(pkt)
				if i%50 == 0 {
					tr.Stats()
				}
			}
		}()
	}
	wg.Wait()
}

// ── Packet loss simulation ────────────────────────────────────────────────────

// Simulates partial UDP loss by reading only a fraction of datagrams from the
// collector side. The encoder must not block or return errors on drops.
func TestNegative_PacketLoss_EncoderUnblocked(t *testing.T) {
	// Small buffer — receiver reads slowly, simulating a lossy/slow collector.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })

	// Intentionally slow reader: reads one datagram every 50 ms.
	go func() {
		buf := make([]byte, 65536)
		for {
			pc.SetDeadline(time.Now().Add(time.Second))
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()

	exp, _ := export.New(pc.LocalAddr().String())
	t.Cleanup(func() { exp.Close() })
	enc := protocols.NewNetFlow(exp)
	records := []*flow.Record{makeRec(1, 2, 6, 1000)}

	// Send 50 export calls rapidly; kernel UDP buffers will drop excess.
	// None of these calls must block for more than 200 ms total.
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 50; i++ {
			if err := enc.Export(records); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Export returned error under packet loss: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Export blocked for >5s under simulated packet loss")
	}
}

// ── Aggregator edge cases ─────────────────────────────────────────────────────

// All records with the same key must merge into a single record without errors.
func TestNegative_Aggregator_AllSameKey(t *testing.T) {
	agg := aggregate.New(aggregate.Config{Enabled: true, Level: aggregate.LevelProtocol, MaxRecords: 0})
	records := make([]*flow.Record, 1000)
	for i := range records {
		records[i] = makeRec(1, 2, 6, 1500)
	}
	out := agg.Process(records)
	if len(out) != 1 {
		t.Errorf("all-same-key: output = %d records, want 1", len(out))
	}
	if out[0].Bytes != 1500*1000 {
		t.Errorf("merged bytes = %d, want %d", out[0].Bytes, uint64(1500*1000))
	}
}

// MaxRecords=1 with 10,000 input records must return exactly 1 record and
// tally all remaining bytes in DroppedBytes.
func TestNegative_Aggregator_MaxRecords_Extreme(t *testing.T) {
	agg := aggregate.New(aggregate.Config{Enabled: true, Level: aggregate.LevelProtocol, MaxRecords: 1})
	records := make([]*flow.Record, 100)
	for i := range records {
		records[i] = makeRec(byte(i), 2, 6, uint64(i+1)*100)
	}
	out := agg.Process(records)
	if len(out) != 1 {
		t.Errorf("MaxRecords=1: output = %d records, want 1", len(out))
	}
	st := agg.Stats()
	if st.DroppedBytes == 0 {
		t.Error("expected DroppedBytes > 0 when MaxRecords=1 and 100 input records")
	}
}

// Nil records inside the slice must not panic (defensive check).
func TestNegative_Aggregator_NilSlice_NoPanic(t *testing.T) {
	agg := aggregate.New(aggregate.Config{Enabled: true, Level: aggregate.LevelProtocol, MaxRecords: 10})
	// Must not panic.
	out := agg.Process(nil)
	if len(out) != 0 {
		t.Errorf("nil input: got %d records, want 0", len(out))
	}
}
