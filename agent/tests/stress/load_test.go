// Stress & load benchmarks for the monitoring agent.
//
// These benchmarks determine the performance ceiling of each subsystem:
//   - How many packets/second the flow tracker can process
//   - How many flow records/second NetFlow and IPFIX encoders can produce
//   - How many records/second the aggregator can merge
//
// Run with:
//   go test ./tests/stress/... -bench=. -benchmem -benchtime=5s
//
// Add -cpuprofile=cpu.prof to identify hot paths.
package stress_test

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/flowmonitor/agent/aggregate"
	"github.com/flowmonitor/agent/export"
	"github.com/flowmonitor/agent/flow"
	"github.com/flowmonitor/agent/protocols"
)

// ── UDP sink ──────────────────────────────────────────────────────────────────

// newSinkExporter creates an Exporter aimed at a UDP server that discards all
// data. This avoids network I/O from dominating benchmark timings.
func newSinkExporter(b *testing.B) *export.Exporter {
	b.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("sink listen: %v", err)
	}
	b.Cleanup(func() { pc.Close() })
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
		b.Fatalf("export.New: %v", err)
	}
	b.Cleanup(func() { exp.Close() })
	return exp
}

// ── Packet factory ────────────────────────────────────────────────────────────

// buildTCPPacket returns a serialised Ethernet+IPv4+TCP frame.
func buildTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16) gopacket.Packet {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
		Window:  65535,
	}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, eth, ip, tcp)
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// buildRecords returns n synthetic flow.Records with distinct source IPs.
func buildRecords(n int) []*flow.Record {
	records := make([]*flow.Record, n)
	for i := range records {
		r := &flow.Record{
			Packets: 100,
			Bytes:   uint64(1500 * (i + 1)),
			Start:   time.Now().Add(-time.Second),
			Last:    time.Now(),
		}
		r.FlowKey.SrcIP = [4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}
		r.FlowKey.DstIP = [4]byte{192, 168, 1, 1}
		r.FlowKey.SrcPort = uint16(1024 + i%60000)
		r.FlowKey.DstPort = 80
		r.FlowKey.Protocol = 6
		records[i] = r
	}
	return records
}

// ── Tracker benchmarks ────────────────────────────────────────────────────────

// BenchmarkTracker_SingleFlow measures the per-packet cost when all packets
// belong to the same flow (most common production pattern).
func BenchmarkTracker_SingleFlow(b *testing.B) {
	tracker := flow.NewTracker(time.Minute, 30*time.Second, 100_000)
	tracker.OnExport(func([]*flow.Record) {})
	pkt := buildTCPPacket(net.ParseIP("10.0.0.1").To4(), net.ParseIP("10.0.0.2").To4(), 12345, 80)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tracker.Process(pkt)
	}
}

// BenchmarkTracker_UniqueFlows measures the per-packet cost when packets cycle
// through a large set of distinct 5-tuples (high allocation pressure).
func BenchmarkTracker_UniqueFlows(b *testing.B) {
	// Pre-build a fixed pool of 10,000 distinct packets and cycle through them.
	const poolSize = 10_000
	tracker := flow.NewTracker(time.Minute, 30*time.Second, 0)
	tracker.OnExport(func([]*flow.Record) {})

	pool := make([]gopacket.Packet, poolSize)
	for i := range pool {
		pool[i] = buildTCPPacket(
			net.ParseIP("10.0.0.1").To4(),
			net.ParseIP("10.0.0.2").To4(),
			uint16(1+i%65534), 80,
		)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tracker.Process(pool[i%poolSize])
	}
}

// BenchmarkTracker_OverflowEviction measures the cost when the cache is full
// and every new packet triggers an eviction.
func BenchmarkTracker_OverflowEviction(b *testing.B) {
	const cacheSize = 100
	tracker := flow.NewTracker(time.Minute, 30*time.Second, cacheSize)
	tracker.OnExport(func([]*flow.Record) {})

	pkts := make([]gopacket.Packet, cacheSize*2)
	for i := range pkts {
		pkts[i] = buildTCPPacket(
			net.ParseIP("10.0.0.1").To4(),
			net.ParseIP("10.0.0.2").To4(),
			uint16(1+i%65534), 80,
		)
	}

	// Pre-fill cache.
	for i := 0; i < cacheSize; i++ {
		tracker.Process(pkts[i])
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tracker.Process(pkts[cacheSize+i%cacheSize])
	}
}

// ── NetFlow encoder benchmarks ────────────────────────────────────────────────

func BenchmarkNetFlow_Export_1(b *testing.B) {
	benchNetFlow(b, 1)
}

func BenchmarkNetFlow_Export_30(b *testing.B) {
	benchNetFlow(b, 30)
}

func BenchmarkNetFlow_Export_300(b *testing.B) {
	benchNetFlow(b, 300)
}

func benchNetFlow(b *testing.B, n int) {
	b.Helper()
	enc := protocols.NewNetFlow(newSinkExporter(b))
	records := buildRecords(n)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := enc.Export(records); err != nil {
			b.Fatalf("Export: %v", err)
		}
	}
	b.SetBytes(int64(n) * 48) // 48 bytes per NetFlow record
}

// ── IPFIX encoder benchmarks ──────────────────────────────────────────────────

func BenchmarkIPFIX_Export_1(b *testing.B) {
	benchIPFIX(b, 1)
}

func BenchmarkIPFIX_Export_20(b *testing.B) {
	benchIPFIX(b, 20)
}

func BenchmarkIPFIX_Export_200(b *testing.B) {
	benchIPFIX(b, 200)
}

func benchIPFIX(b *testing.B, n int) {
	b.Helper()
	enc := protocols.NewIPFIX(newSinkExporter(b))
	// Prime: send template on first call.
	_ = enc.Export(buildRecords(1))
	records := buildRecords(n)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := enc.Export(records); err != nil {
			b.Fatalf("Export: %v", err)
		}
	}
}

// ── Aggregator benchmarks ─────────────────────────────────────────────────────

func BenchmarkAggregator_LevelProtocol_100(b *testing.B) {
	benchAgg(b, aggregate.LevelProtocol, 100)
}

func BenchmarkAggregator_LevelProtocol_1000(b *testing.B) {
	benchAgg(b, aggregate.LevelProtocol, 1000)
}

func BenchmarkAggregator_LevelHostPair_100(b *testing.B) {
	benchAgg(b, aggregate.LevelHostPair, 100)
}

func benchAgg(b *testing.B, level aggregate.Level, n int) {
	b.Helper()
	agg := aggregate.New(aggregate.Config{Enabled: true, Level: level, MaxRecords: 200})
	records := buildRecords(n)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = agg.Process(records)
	}
}

// ── Throughput test ───────────────────────────────────────────────────────────

// TestTracker_Throughput measures the maximum sustained packet rate and
// reports it as a test log (not a benchmark so it is always visible in output).
func TestTracker_Throughput(t *testing.T) {
	tracker := flow.NewTracker(time.Minute, 30*time.Second, 100_000)
	tracker.OnExport(func([]*flow.Record) {})

	pkt := buildTCPPacket(
		net.ParseIP("10.0.0.1").To4(),
		net.ParseIP("10.0.0.2").To4(),
		12345, 80,
	)

	const duration = 2 * time.Second
	deadline := time.Now().Add(duration)
	count := 0
	for time.Now().Before(deadline) {
		tracker.Process(pkt)
		count++
	}
	pps := float64(count) / duration.Seconds()
	t.Logf("Tracker throughput: %.0f packets/sec (%d packets in %s)", pps, count, duration)

	if pps < 10_000 {
		t.Errorf("throughput %.0f pps is below minimum acceptable 10,000 pps", pps)
	}
	t.Logf("Peak flow table size: %d", tracker.Stats().ActiveFlows)
	fmt.Printf("=== Tracker throughput: %.0f pps ===\n", pps)
}
