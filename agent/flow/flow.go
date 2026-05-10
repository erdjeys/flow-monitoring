package flow

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Key is the 5-tuple uniquely identifying a network flow.
type Key struct {
	SrcIP    [4]byte
	DstIP    [4]byte
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
}

// Record accumulates statistics for a single flow.
type Record struct {
	FlowKey  Key
	Packets  uint64
	Bytes    uint64
	Start    time.Time
	Last     time.Time
	TCPFlags uint8
	ToS      uint8

	// Layer 2 addresses captured from the Ethernet header.
	SrcMAC [6]byte
	DstMAC [6]byte

	// IED custom metadata embedded in IPFIX enterprise fields.
	SignalStrength   int8
	EncryptionStatus uint8

	// SensorStatus is the health code polled from the IED:
	//   0 = OK, 1 = WARNING, 2 = ERROR.
	SensorStatus uint8

	// CpuLoad is the agent's own CPU utilisation (0-100 %) at flow-start time.
	CpuLoad uint8

	// Injected impairment state for alert verification.
	PacketLoss   float64
	ExtraLatency time.Duration
}

func (r *Record) SrcNet() net.IP { return net.IP(r.FlowKey.SrcIP[:]) }
func (r *Record) DstNet() net.IP { return net.IP(r.FlowKey.DstIP[:]) }

// ExportFunc is called with expired/active-timeout flow records.
type ExportFunc func([]*Record)

// Problem describes artificial impairment injected into a flow.
type Problem struct {
	PacketLoss   float64
	ExtraLatency time.Duration
}

// Stats is returned by Tracker.Stats().
type Stats struct {
	ActiveFlows       int
	OverflowEvictions uint64
	IPFIXTemplate     []string // filled in by the API handler from the encoder
}

type iedMeta struct {
	SignalStrength   int8   `json:"signal_strength"`
	EncryptionStatus uint8  `json:"encryption_status"`
	SensorStatus     uint8  `json:"sensor_status"`
	DeviceIP         string `json:"device_ip"`
}

// Tracker tracks live flows and triggers exports on timeout.
type Tracker struct {
	mu         sync.Mutex
	flows      map[Key]*Record
	maxFlows   int    // 0 = unlimited
	activeTo   time.Duration
	inactiveTo time.Duration
	onExport   ExportFunc

	overflowEvictions uint64 // atomic counter

	probMu   sync.RWMutex
	problems map[Key]Problem

	iedMu  sync.RWMutex
	iedAPI string
	ied    iedMeta

	cpuMu   sync.RWMutex
	cpuLoad uint8
}

func NewTracker(active, inactive time.Duration, maxFlows int) *Tracker {
	return &Tracker{
		flows:      make(map[Key]*Record),
		maxFlows:   maxFlows,
		activeTo:   active,
		inactiveTo: inactive,
		problems:   make(map[Key]Problem),
	}
}

func (t *Tracker) SetIEDAPI(u string) {
	t.iedAPI = u
	if u != "" {
		go t.pollIED()
	}
}

func (t *Tracker) OnExport(fn ExportFunc) { t.onExport = fn }

// SetCpuLoad stores the agent's current CPU utilisation, called from
// the background /proc/stat poller in main.go.
func (t *Tracker) SetCpuLoad(pct uint8) {
	t.cpuMu.Lock()
	t.cpuLoad = pct
	t.cpuMu.Unlock()
}

func (t *Tracker) InjectProblem(key Key, p Problem) {
	t.probMu.Lock()
	t.problems[key] = p
	t.probMu.Unlock()
}

func (t *Tracker) ClearProblems() {
	t.probMu.Lock()
	t.problems = make(map[Key]Problem)
	t.probMu.Unlock()
}

func (t *Tracker) Stats() Stats {
	t.mu.Lock()
	n := len(t.flows)
	t.mu.Unlock()
	return Stats{
		ActiveFlows:       n,
		OverflowEvictions: atomic.LoadUint64(&t.overflowEvictions),
	}
}

func (t *Tracker) Process(pkt gopacket.Packet) {
	key, byteCount, flags, tos, ok := extractKey(pkt)
	if !ok {
		return
	}

	var srcMAC, dstMAC [6]byte
	if eth, ok := pkt.LinkLayer().(*layers.Ethernet); ok {
		copy(srcMAC[:], eth.SrcMAC)
		copy(dstMAC[:], eth.DstMAC)
	}

	now := pkt.Metadata().Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	t.mu.Lock()
	rec, exists := t.flows[key]
	if !exists {
		// Cache overflow: evict the oldest flow to make room.
		if t.maxFlows > 0 && len(t.flows) >= t.maxFlows {
			t.evictOldest()
		}

		rec = &Record{FlowKey: key, Start: now, SrcMAC: srcMAC, DstMAC: dstMAC}
		t.flows[key] = rec

		// Stamp IED metadata on flows that involve the sensor.
		t.iedMu.RLock()
		if t.ied.DeviceIP != "" {
			if iedIP := net.ParseIP(t.ied.DeviceIP).To4(); iedIP != nil {
				var iedArr [4]byte
				copy(iedArr[:], iedIP)
				if key.SrcIP == iedArr || key.DstIP == iedArr {
					rec.SignalStrength = t.ied.SignalStrength
					rec.EncryptionStatus = t.ied.EncryptionStatus
					rec.SensorStatus = t.ied.SensorStatus
				}
			}
		}
		t.iedMu.RUnlock()

		// Stamp the agent's current CPU load at flow-creation time.
		t.cpuMu.RLock()
		rec.CpuLoad = t.cpuLoad
		t.cpuMu.RUnlock()
	}
	rec.Packets++
	rec.Bytes += uint64(byteCount)
	rec.Last = now
	rec.TCPFlags |= flags
	rec.ToS = tos

	t.probMu.RLock()
	if p, ok := t.problems[key]; ok {
		rec.PacketLoss = p.PacketLoss
		rec.ExtraLatency = p.ExtraLatency
	}
	t.probMu.RUnlock()
	t.mu.Unlock()
}

// evictOldest removes the flow with the earliest Start time and exports it.
// Must be called with t.mu held.
func (t *Tracker) evictOldest() {
	var oldestKey Key
	var oldestStart time.Time
	first := true
	for k, r := range t.flows {
		if first || r.Start.Before(oldestStart) {
			oldestKey = k
			oldestStart = r.Start
			first = false
		}
	}
	if evicted, ok := t.flows[oldestKey]; ok {
		atomic.AddUint64(&t.overflowEvictions, 1)
		delete(t.flows, oldestKey)
		// Export asynchronously so we don't hold the mutex during I/O.
		if t.onExport != nil {
			rec := *evicted
			go t.onExport([]*Record{&rec})
		}
		log.Printf("[OVERFLOW] cache full (%d/%d) — evicted oldest flow %v→%v started %s ago",
			len(t.flows)+1, t.maxFlows,
			net.IP(oldestKey.SrcIP[:]), net.IP(oldestKey.DstIP[:]),
			time.Since(oldestStart).Round(time.Second))
	}
}

func (t *Tracker) Run() {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for range tick.C {
		t.checkTimeouts()
	}
}

func (t *Tracker) checkTimeouts() {
	now := time.Now()
	var expired []*Record

	t.mu.Lock()
	for key, rec := range t.flows {
		if now.Sub(rec.Last) > t.inactiveTo {
			expired = append(expired, rec)
			delete(t.flows, key)
		} else if now.Sub(rec.Start) > t.activeTo {
			clone := *rec
			expired = append(expired, &clone)
			rec.Start = now
			rec.Packets = 0
			rec.Bytes = 0
		}
	}
	t.mu.Unlock()

	if len(expired) > 0 && t.onExport != nil {
		t.onExport(expired)
	}
}

func (t *Tracker) pollIED() {
	// Derive the device IP from the IED API URL for flow-key matching.
	if u, err := url.Parse(t.iedAPI); err == nil {
		host := u.Hostname()
		t.iedMu.Lock()
		t.ied.DeviceIP = host
		t.iedMu.Unlock()
	}

	for range time.Tick(10 * time.Second) {
		resp, err := http.Get(t.iedAPI + "/status")
		if err != nil {
			log.Printf("IED poll: %v", err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var meta iedMeta
		if err := json.Unmarshal(body, &meta); err == nil {
			t.iedMu.Lock()
			meta.DeviceIP = t.ied.DeviceIP // preserve URL-derived IP
			t.ied = meta
			t.iedMu.Unlock()
		}
	}
}

func extractKey(pkt gopacket.Packet) (key Key, size int, tcpFlags uint8, tos uint8, ok bool) {
	netLayer := pkt.NetworkLayer()
	if netLayer == nil {
		return
	}
	ipv4, isV4 := netLayer.(*layers.IPv4)
	if !isV4 {
		return
	}
	copy(key.SrcIP[:], ipv4.SrcIP.To4())
	copy(key.DstIP[:], ipv4.DstIP.To4())
	key.Protocol = uint8(ipv4.Protocol)
	tos = ipv4.TOS
	size = len(pkt.Data())
	ok = true

	switch l := pkt.TransportLayer().(type) {
	case *layers.TCP:
		key.SrcPort = uint16(l.SrcPort)
		key.DstPort = uint16(l.DstPort)
		if l.SYN {
			tcpFlags |= 0x02
		}
		if l.ACK {
			tcpFlags |= 0x10
		}
		if l.FIN {
			tcpFlags |= 0x01
		}
		if l.RST {
			tcpFlags |= 0x04
		}
		if l.PSH {
			tcpFlags |= 0x08
		}
		if l.URG {
			tcpFlags |= 0x20
		}
	case *layers.UDP:
		key.SrcPort = uint16(l.SrcPort)
		key.DstPort = uint16(l.DstPort)
	}
	return
}
