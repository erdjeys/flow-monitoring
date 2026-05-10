// Package aggregate implements intelligent flow aggregation to reduce
// export bandwidth on constrained links (narrow-channel optimization).
//
// How it works
// ────────────
//   1. Protocol-level merge  – flows sharing (srcIP, dstIP, protocol) are
//      merged into one record: packets and bytes are summed, TCP flags are
//      OR-ed, timestamps span the earliest start and latest end.
//
//   2. MaxRecords cap        – if the merged set still exceeds MaxRecords,
//      only the top-N flows by byte count are kept. The discarded bytes
//      are tallied in DroppedBytes so the operator knows the data loss.
//
// Statistics (TotalIn / TotalOut / DroppedBytes) accumulate monotonically
// and are exposed via the agent's /api/aggregate endpoint.
package aggregate

import (
	"sort"
	"sync"
	"sync/atomic"

	"github.com/flowmonitor/agent/flow"
)

// Level controls how aggressively flows are merged.
type Level string

const (
	// LevelNone disables aggregation; records pass through unchanged.
	LevelNone Level = "none"

	// LevelProtocol merges flows that share (srcIP, dstIP, protocol).
	// Port information is lost but per-protocol byte counts are preserved.
	// This is the recommended default.
	LevelProtocol Level = "protocol"

	// LevelHostPair merges all flows between the same host pair regardless
	// of protocol. Maximum compression; loses protocol breakdown.
	LevelHostPair Level = "host_pair"
)

// Config controls aggregation behaviour.
type Config struct {
	// Enabled switches aggregation on or off without changing other settings.
	Enabled bool `json:"enabled"`

	// Level sets the merge granularity.
	Level Level `json:"level"`

	// MaxRecords caps the number of records emitted per export batch.
	// 0 = unlimited (only merging is applied, no top-N drop).
	MaxRecords int `json:"max_records"`
}

// Stats is a snapshot of aggregation statistics.
type Stats struct {
	TotalIn          uint64  `json:"total_in"`           // flows received for processing
	TotalOut         uint64  `json:"total_out"`          // flows emitted after aggregation
	DroppedBytes     uint64  `json:"dropped_bytes"`      // bytes belonging to top-N-dropped flows
	CompressionRatio float64 `json:"compression_ratio"`  // TotalOut / TotalIn (1.0 = no compression)
}

// Aggregator merges flow records before they are encoded and sent.
// It is safe for concurrent use.
type Aggregator struct {
	cfgMu sync.RWMutex
	cfg   Config

	totalIn      uint64 // atomic
	totalOut     uint64 // atomic
	droppedBytes uint64 // atomic
}

// New returns an Aggregator with the given initial configuration.
func New(cfg Config) *Aggregator {
	return &Aggregator{cfg: cfg}
}

// GetConfig returns the current configuration.
func (a *Aggregator) GetConfig() Config {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return a.cfg
}

// SetConfig replaces the current configuration atomically.
func (a *Aggregator) SetConfig(cfg Config) {
	a.cfgMu.Lock()
	a.cfg = cfg
	a.cfgMu.Unlock()
}

// Stats returns a current statistics snapshot.
func (a *Aggregator) Stats() Stats {
	in := atomic.LoadUint64(&a.totalIn)
	out := atomic.LoadUint64(&a.totalOut)
	dropped := atomic.LoadUint64(&a.droppedBytes)
	ratio := 1.0
	if in > 0 {
		ratio = float64(out) / float64(in)
	}
	return Stats{
		TotalIn:          in,
		TotalOut:         out,
		DroppedBytes:     dropped,
		CompressionRatio: ratio,
	}
}

// ── Merge keys ────────────────────────────────────────────────────────────────

type protoKey struct {
	SrcIP    [4]byte
	DstIP    [4]byte
	Protocol uint8
}

type pairKey struct {
	SrcIP [4]byte
	DstIP [4]byte
}

// ── Process ───────────────────────────────────────────────────────────────────

// Process aggregates records according to the current configuration and
// returns the reduced set.  The input slice is never modified.
func (a *Aggregator) Process(records []*flow.Record) []*flow.Record {
	a.cfgMu.RLock()
	cfg := a.cfg
	a.cfgMu.RUnlock()

	atomic.AddUint64(&a.totalIn, uint64(len(records)))

	if !cfg.Enabled || len(records) == 0 || cfg.Level == LevelNone {
		atomic.AddUint64(&a.totalOut, uint64(len(records)))
		return records
	}

	// ── Step 1: merge ────────────────────────────────────────────────────────
	var merged []*flow.Record
	switch cfg.Level {
	case LevelHostPair:
		merged = mergeByHostPair(records)
	default: // LevelProtocol
		merged = mergeByProtocol(records)
	}

	// ── Step 2: top-N cap ────────────────────────────────────────────────────
	var dropped uint64
	if cfg.MaxRecords > 0 && len(merged) > cfg.MaxRecords {
		// Sort descending by bytes so we keep the highest-traffic flows.
		sort.Slice(merged, func(i, j int) bool {
			return merged[i].Bytes > merged[j].Bytes
		})
		// Tally bytes that will be dropped (below the cut-off).
		for _, r := range merged[cfg.MaxRecords:] {
			dropped += r.Bytes
		}
		merged = merged[:cfg.MaxRecords]
	}

	atomic.AddUint64(&a.totalOut, uint64(len(merged)))
	if dropped > 0 {
		atomic.AddUint64(&a.droppedBytes, dropped)
	}
	return merged
}

// ── Internal merge helpers ────────────────────────────────────────────────────

func mergeByProtocol(records []*flow.Record) []*flow.Record {
	table := make(map[protoKey]*flow.Record, len(records))
	for _, r := range records {
		k := protoKey{SrcIP: r.FlowKey.SrcIP, DstIP: r.FlowKey.DstIP, Protocol: r.FlowKey.Protocol}
		if m, ok := table[k]; ok {
			mergeInto(m, r)
		} else {
			clone := *r
			table[k] = &clone
		}
	}
	return mapValues(table)
}

func mergeByHostPair(records []*flow.Record) []*flow.Record {
	table := make(map[pairKey]*flow.Record, len(records))
	for _, r := range records {
		k := pairKey{SrcIP: r.FlowKey.SrcIP, DstIP: r.FlowKey.DstIP}
		if m, ok := table[k]; ok {
			mergeInto(m, r)
		} else {
			clone := *r
			table[k] = &clone
		}
	}
	return mapValues(table)
}

// mergeInto folds src into dst, accumulating traffic counters.
func mergeInto(dst, src *flow.Record) {
	dst.Packets += src.Packets
	dst.Bytes += src.Bytes
	dst.TCPFlags |= src.TCPFlags
	if src.Start.Before(dst.Start) {
		dst.Start = src.Start
	}
	if src.Last.After(dst.Last) {
		dst.Last = src.Last
	}
	// Keep enterprise metadata from the first record seen (dst already holds it).
}

func mapValues[K comparable](m map[K]*flow.Record) []*flow.Record {
	out := make([]*flow.Record, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}
