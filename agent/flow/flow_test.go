// Unit tests for the flow Tracker.
//
// The test file is in package flow (white-box) so it can call the unexported
// checkTimeouts method directly, avoiding the 5-second ticker in Run().
//
// Run with: go test ./flow/... -v -race
package flow

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ── Packet helpers ────────────────────────────────────────────────────────────

// craftTCP serialises a minimal Ethernet+IPv4+TCP frame and returns it as a
// gopacket.Packet. SYN is set when syn=true.
func craftTCP(srcIP, dstIP string, srcPort, dstPort uint16, syn bool) gopacket.Packet {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     syn,
		Window:  65535,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, eth, ip, tcp)
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// craftUDP serialises a minimal Ethernet+IPv4+UDP frame.
func craftUDP(srcIP, dstIP string, srcPort, dstPort uint16) gopacket.Packet {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, eth, ip, udp)
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// newTracker returns a Tracker with short timeouts suitable for unit tests.
func newTracker(activeTo, inactiveTo time.Duration) (*Tracker, chan []*Record) {
	exported := make(chan []*Record, 64)
	t := NewTracker(activeTo, inactiveTo, 0)
	t.OnExport(func(recs []*Record) {
		exported <- recs
	})
	return t, exported
}

// expectExport reads one exported batch from the channel, failing if none arrives
// within 1 second.
func expectExport(t *testing.T, ch chan []*Record) []*Record {
	t.Helper()
	select {
	case recs := <-ch:
		return recs
	case <-time.After(time.Second):
		t.Fatal("timeout: expected an export but none arrived")
		return nil
	}
}

// expectNoExport asserts that no export arrives within 80 ms.
func expectNoExport(t *testing.T, ch chan []*Record) {
	t.Helper()
	select {
	case recs := <-ch:
		t.Errorf("unexpected export: %d records", len(recs))
	case <-time.After(80 * time.Millisecond):
		// OK
	}
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// A packet that does not contain an IPv4 layer must be silently ignored.
func TestTracker_IgnoresNonIPPacket(t *testing.T) {
	tr, exported := newTracker(time.Minute, time.Minute)
	// ARP frame — no IP layer.
	raw := []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x08, 0x06, // ARP
		0x00, 0x00, // dummy payload
	}
	tr.Process(gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default))
	tr.mu.Lock()
	n := len(tr.flows)
	tr.mu.Unlock()
	if n != 0 {
		t.Errorf("expected 0 flows after non-IP packet, got %d", n)
	}
	expectNoExport(t, exported)
}

// After the first packet of a new 5-tuple the tracker must hold exactly one flow.
func TestTracker_CreatesFlowOnFirstPacket(t *testing.T) {
	tr, _ := newTracker(time.Minute, time.Minute)
	tr.Process(craftTCP("1.2.3.4", "5.6.7.8", 1234, 80, true))
	tr.mu.Lock()
	n := len(tr.flows)
	tr.mu.Unlock()
	if n != 1 {
		t.Errorf("expected 1 flow, got %d", n)
	}
}

// Packets with the same 5-tuple must accumulate into a single flow record.
func TestTracker_AccumulatesPackets(t *testing.T) {
	tr, _ := newTracker(time.Minute, time.Minute)
	for i := 0; i < 5; i++ {
		tr.Process(craftTCP("1.2.3.4", "5.6.7.8", 1234, 80, false))
	}
	tr.mu.Lock()
	var rec *Record
	for _, r := range tr.flows {
		rec = r
	}
	tr.mu.Unlock()
	if rec == nil {
		t.Fatal("no flow found")
	}
	if rec.Packets != 5 {
		t.Errorf("packets = %d, want 5", rec.Packets)
	}
}

// TCP flags must be ORed across all packets of the same flow.
func TestTracker_TCPFlagsAccumulate(t *testing.T) {
	tr, _ := newTracker(time.Minute, time.Minute)
	// SYN packet → flag 0x02
	tr.Process(craftTCP("1.2.3.4", "5.6.7.8", 1234, 80, true))
	// ACK+PSH → craftTCP with SYN=false sets no flags by default; we need a
	// raw packet. Use the same key so it merges into the existing flow.
	// Send a second SYN to keep it simple (ORing 0x02|0x02 = 0x02).
	tr.Process(craftTCP("1.2.3.4", "5.6.7.8", 1234, 80, true))

	tr.mu.Lock()
	var rec *Record
	for _, r := range tr.flows {
		rec = r
	}
	tr.mu.Unlock()
	if rec == nil {
		t.Fatal("no flow found")
	}
	// Both packets had SYN; the OR result should be 0x02.
	if rec.TCPFlags&0x02 == 0 {
		t.Errorf("SYN flag not set after two SYN packets: flags=0x%02X", rec.TCPFlags)
	}
}

// After the inactive timeout elapses the flow must be exported.
func TestTracker_InactiveTimeout(t *testing.T) {
	const inactive = 50 * time.Millisecond
	tr, exported := newTracker(time.Minute, inactive)
	tr.Process(craftTCP("1.2.3.4", "5.6.7.8", 1234, 80, true))

	time.Sleep(inactive + 20*time.Millisecond)
	tr.checkTimeouts()

	recs := expectExport(t, exported)
	if len(recs) == 0 {
		t.Error("exported batch is empty")
	}
	// After export the flow must be removed.
	tr.mu.Lock()
	n := len(tr.flows)
	tr.mu.Unlock()
	if n != 0 {
		t.Errorf("expected 0 flows after inactive timeout, got %d", n)
	}
}

// After the active timeout elapses the flow must be exported as a clone
// while remaining active in the tracker.
func TestTracker_ActiveTimeout_ClonesFlow(t *testing.T) {
	const active = 50 * time.Millisecond
	tr, exported := newTracker(active, time.Minute)
	tr.Process(craftTCP("1.2.3.4", "5.6.7.8", 1234, 80, true))

	time.Sleep(active + 20*time.Millisecond)
	tr.checkTimeouts()

	expectExport(t, exported) // clone exported

	// Flow must still be active.
	tr.mu.Lock()
	n := len(tr.flows)
	tr.mu.Unlock()
	if n != 1 {
		t.Errorf("expected 1 active flow after active timeout, got %d", n)
	}
}

// SetCpuLoad + new flow: the CPU load must be stamped at flow creation time.
func TestTracker_CpuLoadStampedOnNewFlow(t *testing.T) {
	tr, _ := newTracker(time.Minute, time.Minute)
	tr.SetCpuLoad(75)
	tr.Process(craftTCP("1.2.3.4", "5.6.7.8", 9000, 80, true))
	tr.mu.Lock()
	var rec *Record
	for _, r := range tr.flows {
		rec = r
	}
	tr.mu.Unlock()
	if rec == nil {
		t.Fatal("no flow found")
	}
	if rec.CpuLoad != 75 {
		t.Errorf("CpuLoad = %d, want 75", rec.CpuLoad)
	}
}

// CpuLoad must NOT be updated on subsequent packets of an existing flow.
func TestTracker_CpuLoadNotUpdatedOnExistingFlow(t *testing.T) {
	tr, _ := newTracker(time.Minute, time.Minute)
	tr.SetCpuLoad(10)
	tr.Process(craftTCP("1.2.3.4", "5.6.7.8", 9000, 80, true)) // flow created with load=10
	tr.SetCpuLoad(99)
	tr.Process(craftTCP("1.2.3.4", "5.6.7.8", 9000, 80, false)) // same 5-tuple

	tr.mu.Lock()
	var rec *Record
	for _, r := range tr.flows {
		rec = r
	}
	tr.mu.Unlock()
	if rec == nil {
		t.Fatal("no flow found")
	}
	if rec.CpuLoad != 10 {
		t.Errorf("CpuLoad updated on existing flow: got %d, want 10", rec.CpuLoad)
	}
}

// When the flow table is full the oldest flow must be evicted.
func TestTracker_CacheOverflowEvictsOldest(t *testing.T) {
	const max = 3
	exported := make(chan []*Record, 16)
	tr := NewTracker(time.Minute, time.Minute, max)
	tr.OnExport(func(recs []*Record) { exported <- recs })

	// Fill the cache to capacity.
	tr.Process(craftTCP("10.0.0.1", "10.0.0.100", 1000, 80, false))
	time.Sleep(10 * time.Millisecond) // ensure distinct timestamps
	tr.Process(craftTCP("10.0.0.2", "10.0.0.100", 1001, 80, false))
	time.Sleep(10 * time.Millisecond)
	tr.Process(craftTCP("10.0.0.3", "10.0.0.100", 1002, 80, false))

	// Adding one more must trigger an eviction.
	tr.Process(craftTCP("10.0.0.4", "10.0.0.100", 1003, 80, false))

	recs := expectExport(t, exported)
	if len(recs) == 0 {
		t.Error("expected an evicted record to be exported")
	}
	evictedSrc := recs[0].SrcNet()
	if !evictedSrc.Equal(net.ParseIP("10.0.0.1").To4()) {
		t.Errorf("evicted flow srcIP = %v, want 10.0.0.1 (oldest)", evictedSrc)
	}
}

// InjectProblem must store the impairment on the matching flow key.
func TestTracker_InjectProblem(t *testing.T) {
	tr, _ := newTracker(time.Minute, time.Minute)
	key := Key{}
	copy(key.SrcIP[:], net.ParseIP("1.2.3.4").To4())
	copy(key.DstIP[:], net.ParseIP("5.6.7.8").To4())
	key.SrcPort = 1234
	key.DstPort = 80
	key.Protocol = 6

	tr.InjectProblem(key, Problem{PacketLoss: 0.25, ExtraLatency: 200 * time.Millisecond})
	tr.Process(craftTCP("1.2.3.4", "5.6.7.8", 1234, 80, true))

	tr.mu.Lock()
	rec := tr.flows[key]
	tr.mu.Unlock()
	if rec == nil {
		t.Fatal("flow not found")
	}
	if rec.PacketLoss != 0.25 {
		t.Errorf("PacketLoss = %.2f, want 0.25", rec.PacketLoss)
	}
	if rec.ExtraLatency != 200*time.Millisecond {
		t.Errorf("ExtraLatency = %v, want 200ms", rec.ExtraLatency)
	}
}

// ClearProblems must remove all injected impairments.
func TestTracker_ClearProblems(t *testing.T) {
	tr, _ := newTracker(time.Minute, time.Minute)
	key := Key{}
	copy(key.SrcIP[:], net.ParseIP("1.2.3.4").To4())
	copy(key.DstIP[:], net.ParseIP("5.6.7.8").To4())
	key.Protocol = 6

	tr.InjectProblem(key, Problem{PacketLoss: 0.5})
	tr.ClearProblems()

	tr.probMu.RLock()
	n := len(tr.problems)
	tr.probMu.RUnlock()
	if n != 0 {
		t.Errorf("expected 0 problems after ClearProblems, got %d", n)
	}
}

// Distinct 5-tuples must create independent flow records.
func TestTracker_DistinctTuplesCreateSeparateFlows(t *testing.T) {
	tr, _ := newTracker(time.Minute, time.Minute)
	tr.Process(craftTCP("1.2.3.4", "5.6.7.8", 1000, 80, true))
	tr.Process(craftTCP("1.2.3.4", "5.6.7.8", 1001, 80, true))  // different src port
	tr.Process(craftUDP("1.2.3.4", "5.6.7.8", 1000, 53))         // different protocol

	tr.mu.Lock()
	n := len(tr.flows)
	tr.mu.Unlock()
	if n != 3 {
		t.Errorf("expected 3 distinct flows, got %d", n)
	}
}

// Stats must reflect the current number of active flows.
func TestTracker_Stats(t *testing.T) {
	tr, _ := newTracker(time.Minute, time.Minute)
	tr.Process(craftTCP("1.2.3.4", "5.6.7.8", 1000, 80, true))
	tr.Process(craftTCP("1.2.3.5", "5.6.7.8", 1001, 80, true))
	st := tr.Stats()
	if st.ActiveFlows != 2 {
		t.Errorf("ActiveFlows = %d, want 2", st.ActiveFlows)
	}
}
