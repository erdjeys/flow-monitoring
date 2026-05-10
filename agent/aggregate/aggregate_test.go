// Unit tests for the flow aggregator.
//
// Run with: go test ./aggregate/... -v
package aggregate

import (
	"net"
	"testing"
	"time"

	"github.com/flowmonitor/agent/flow"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

func rec(srcIP, dstIP string, proto uint8, packets, bytes uint64) *flow.Record {
	r := &flow.Record{
		Packets: packets,
		Bytes:   bytes,
		Start:   time.Now(),
		Last:    time.Now(),
	}
	copy(r.FlowKey.SrcIP[:], net.ParseIP(srcIP).To4())
	copy(r.FlowKey.DstIP[:], net.ParseIP(dstIP).To4())
	r.FlowKey.Protocol = proto
	return r
}

// findByProto looks for a merged record with the given protocol.
func findByProto(recs []*flow.Record, proto uint8) *flow.Record {
	for _, r := range recs {
		if r.FlowKey.Protocol == proto {
			return r
		}
	}
	return nil
}

// ── LevelNone ────────────────────────────────────────────────────────────────

// When disabled the aggregator must return the input slice unchanged.
func TestAggregator_Disabled_PassThrough(t *testing.T) {
	agg := New(Config{Enabled: false, Level: LevelProtocol, MaxRecords: 100})
	in := []*flow.Record{
		rec("1.1.1.1", "2.2.2.2", 6, 10, 1000),
		rec("1.1.1.1", "2.2.2.2", 6, 5, 500),
	}
	out := agg.Process(in)
	if len(out) != len(in) {
		t.Errorf("disabled: output len = %d, want %d", len(out), len(in))
	}
}

// LevelNone must pass records through without merging.
func TestAggregator_LevelNone_NoMerge(t *testing.T) {
	agg := New(Config{Enabled: true, Level: LevelNone, MaxRecords: 100})
	in := []*flow.Record{
		rec("1.1.1.1", "2.2.2.2", 6, 10, 1000),
		rec("1.1.1.1", "2.2.2.2", 6, 5, 500),
	}
	out := agg.Process(in)
	if len(out) != 2 {
		t.Errorf("LevelNone: output len = %d, want 2 (no merging)", len(out))
	}
}

// ── LevelProtocol ────────────────────────────────────────────────────────────

// Flows with the same (srcIP, dstIP, proto) must be merged into one record.
func TestAggregator_LevelProtocol_MergesSameTuple(t *testing.T) {
	agg := New(Config{Enabled: true, Level: LevelProtocol, MaxRecords: 100})
	in := []*flow.Record{
		rec("1.1.1.1", "2.2.2.2", 6, 10, 1000),
		rec("1.1.1.1", "2.2.2.2", 6, 5, 500),
	}
	out := agg.Process(in)
	if len(out) != 1 {
		t.Errorf("LevelProtocol: output len = %d, want 1 (merged)", len(out))
	}
	if out[0].Packets != 15 {
		t.Errorf("merged packets = %d, want 15", out[0].Packets)
	}
	if out[0].Bytes != 1500 {
		t.Errorf("merged bytes = %d, want 1500", out[0].Bytes)
	}
}

// Different protocols for the same host pair must NOT be merged at LevelProtocol.
func TestAggregator_LevelProtocol_KeepsProtocolSeparate(t *testing.T) {
	agg := New(Config{Enabled: true, Level: LevelProtocol, MaxRecords: 100})
	in := []*flow.Record{
		rec("1.1.1.1", "2.2.2.2", 6, 10, 1000),  // TCP
		rec("1.1.1.1", "2.2.2.2", 17, 5, 500),    // UDP
	}
	out := agg.Process(in)
	if len(out) != 2 {
		t.Errorf("LevelProtocol: different protocols merged (got %d records, want 2)", len(out))
	}
	tcp := findByProto(out, 6)
	udp := findByProto(out, 17)
	if tcp == nil || udp == nil {
		t.Errorf("expected both TCP and UDP records in output")
	}
}

// TCP flags must be ORed across merged records.
func TestAggregator_LevelProtocol_ORsTCPFlags(t *testing.T) {
	agg := New(Config{Enabled: true, Level: LevelProtocol, MaxRecords: 100})
	r1 := rec("1.1.1.1", "2.2.2.2", 6, 1, 60)
	r1.TCPFlags = 0x02 // SYN
	r2 := rec("1.1.1.1", "2.2.2.2", 6, 1, 60)
	r2.TCPFlags = 0x10 // ACK
	out := agg.Process([]*flow.Record{r1, r2})
	if len(out) != 1 {
		t.Fatalf("expected 1 merged record, got %d", len(out))
	}
	if out[0].TCPFlags != 0x12 {
		t.Errorf("merged TCPFlags = 0x%02X, want 0x12 (SYN|ACK)", out[0].TCPFlags)
	}
}

// The merged record must span the earliest Start and latest Last timestamps.
func TestAggregator_LevelProtocol_SpansTimestamps(t *testing.T) {
	agg := New(Config{Enabled: true, Level: LevelProtocol, MaxRecords: 100})
	early := time.Now().Add(-10 * time.Second)
	late := time.Now()
	r1 := rec("1.1.1.1", "2.2.2.2", 6, 1, 60)
	r1.Start = early.Add(time.Second)
	r1.Last = late.Add(-time.Second)
	r2 := rec("1.1.1.1", "2.2.2.2", 6, 1, 60)
	r2.Start = early
	r2.Last = late
	out := agg.Process([]*flow.Record{r1, r2})
	if len(out) != 1 {
		t.Fatalf("expected 1 merged record, got %d", len(out))
	}
	if !out[0].Start.Equal(early) {
		t.Errorf("Start = %v, want %v (earliest)", out[0].Start, early)
	}
	if !out[0].Last.Equal(late) {
		t.Errorf("Last = %v, want %v (latest)", out[0].Last, late)
	}
}

// ── LevelHostPair ─────────────────────────────────────────────────────────────

// All flows between the same host pair must be merged, regardless of protocol.
func TestAggregator_LevelHostPair_MergesAllProtocols(t *testing.T) {
	agg := New(Config{Enabled: true, Level: LevelHostPair, MaxRecords: 100})
	in := []*flow.Record{
		rec("1.1.1.1", "2.2.2.2", 6, 10, 1000),
		rec("1.1.1.1", "2.2.2.2", 17, 5, 500),
		rec("1.1.1.1", "2.2.2.2", 1, 2, 200),
	}
	out := agg.Process(in)
	if len(out) != 1 {
		t.Errorf("LevelHostPair: output len = %d, want 1 (all protocols merged)", len(out))
	}
	if out[0].Bytes != 1700 {
		t.Errorf("merged bytes = %d, want 1700", out[0].Bytes)
	}
}

// Different host pairs must remain separate at LevelHostPair.
func TestAggregator_LevelHostPair_KeepsPairsSeparate(t *testing.T) {
	agg := New(Config{Enabled: true, Level: LevelHostPair, MaxRecords: 100})
	in := []*flow.Record{
		rec("1.1.1.1", "2.2.2.2", 6, 10, 1000),
		rec("1.1.1.1", "3.3.3.3", 6, 5, 500), // different destination
	}
	out := agg.Process(in)
	if len(out) != 2 {
		t.Errorf("LevelHostPair: different pairs merged (got %d records, want 2)", len(out))
	}
}

// ── MaxRecords cap ────────────────────────────────────────────────────────────

// When the merged result exceeds MaxRecords, only the top-N by bytes are kept.
func TestAggregator_MaxRecords_KeepsTopN(t *testing.T) {
	agg := New(Config{Enabled: true, Level: LevelProtocol, MaxRecords: 2})
	in := []*flow.Record{
		rec("1.1.1.1", "2.2.2.2", 6, 1, 100),
		rec("1.1.1.2", "2.2.2.2", 6, 1, 9000), // highest bytes
		rec("1.1.1.3", "2.2.2.2", 6, 1, 5000), // second highest
	}
	out := agg.Process(in)
	if len(out) != 2 {
		t.Errorf("MaxRecords=2: output len = %d, want 2", len(out))
	}
	// Both retained records must have ≥ 5000 bytes.
	for _, r := range out {
		if r.Bytes < 5000 {
			t.Errorf("low-byte flow retained: bytes = %d (should have been dropped)", r.Bytes)
		}
	}
}

// Bytes belonging to dropped records must be tallied in DroppedBytes.
func TestAggregator_MaxRecords_TalliesDroppedBytes(t *testing.T) {
	agg := New(Config{Enabled: true, Level: LevelProtocol, MaxRecords: 1})
	in := []*flow.Record{
		rec("1.1.1.1", "2.2.2.2", 6, 1, 9000), // kept
		rec("1.1.1.2", "2.2.2.2", 6, 1, 1000), // dropped
	}
	agg.Process(in)
	if st := agg.Stats(); st.DroppedBytes != 1000 {
		t.Errorf("DroppedBytes = %d, want 1000", st.DroppedBytes)
	}
}

// MaxRecords=0 means unlimited — all merged records pass through.
func TestAggregator_MaxRecords_Zero_Unlimited(t *testing.T) {
	agg := New(Config{Enabled: true, Level: LevelProtocol, MaxRecords: 0})
	in := make([]*flow.Record, 50)
	for i := range in {
		// Give each a unique srcIP so none are merged.
		in[i] = rec("1.1.1."+string(rune('a'+i%26)), "2.2.2.2", 6, 1, 100)
	}
	// Override srcIPs properly:
	for i := range in {
		src := [4]byte{10, 0, byte(i / 256), byte(i % 256)}
		in[i].FlowKey.SrcIP = src
	}
	out := agg.Process(in)
	if len(out) != 50 {
		t.Errorf("MaxRecords=0: output len = %d, want 50", len(out))
	}
}

// ── Statistics ───────────────────────────────────────────────────────────────

func TestAggregator_Stats_TotalInOut(t *testing.T) {
	agg := New(Config{Enabled: true, Level: LevelProtocol, MaxRecords: 100})
	in := []*flow.Record{
		rec("1.1.1.1", "2.2.2.2", 6, 1, 100),
		rec("1.1.1.1", "2.2.2.2", 6, 1, 100), // merged with above
		rec("1.1.1.2", "2.2.2.2", 6, 1, 100), // separate
	}
	agg.Process(in)
	st := agg.Stats()
	if st.TotalIn != 3 {
		t.Errorf("TotalIn = %d, want 3", st.TotalIn)
	}
	if st.TotalOut != 2 {
		t.Errorf("TotalOut = %d, want 2", st.TotalOut)
	}
	if st.CompressionRatio > 1.0 {
		t.Errorf("CompressionRatio = %.2f, should be ≤ 1.0 when compressing", st.CompressionRatio)
	}
}

// SetConfig must take effect on the next Process call.
func TestAggregator_SetConfig_HotReload(t *testing.T) {
	agg := New(Config{Enabled: true, Level: LevelProtocol, MaxRecords: 100})
	in := []*flow.Record{
		rec("1.1.1.1", "2.2.2.2", 6, 1, 100),
		rec("1.1.1.1", "2.2.2.2", 6, 1, 100),
	}
	out1 := agg.Process(in)
	if len(out1) != 1 {
		t.Errorf("before SetConfig: output = %d, want 1 (merged)", len(out1))
	}

	agg.SetConfig(Config{Enabled: false})
	out2 := agg.Process(in)
	if len(out2) != 2 {
		t.Errorf("after SetConfig(disabled): output = %d, want 2 (pass-through)", len(out2))
	}
}

// Empty input must produce empty output without panicking.
func TestAggregator_EmptyInput(t *testing.T) {
	agg := New(Config{Enabled: true, Level: LevelProtocol, MaxRecords: 10})
	out := agg.Process(nil)
	if len(out) != 0 {
		t.Errorf("nil input produced %d records, want 0", len(out))
	}
	out2 := agg.Process([]*flow.Record{})
	if len(out2) != 0 {
		t.Errorf("empty input produced %d records, want 0", len(out2))
	}
}
