// Package protocols implements NetFlow v5, IPFIX v10, and sFlow v5 export encoding.
package protocols

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"

	"github.com/flowmonitor/agent/export"
	"github.com/flowmonitor/agent/flow"
)

// ── Shared helpers ────────────────────────────────────────────────────────────

func toV4(ip net.IP) []byte {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return net.IPv4zero.To4()
}

func be16(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }
func be64(v uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, v); return b }

// ── NetFlow v5 ────────────────────────────────────────────────────────────────

const nfMaxPerPkt = 30

var (
	nfSeq       uint32
	nfStartTime = time.Now()
)

// NetFlowEncoder encodes flow records as NetFlow v5 UDP datagrams.
type NetFlowEncoder struct{ exp *export.Exporter }

func NewNetFlow(exp *export.Exporter) *NetFlowEncoder { return &NetFlowEncoder{exp: exp} }

func (e *NetFlowEncoder) Export(records []*flow.Record) error {
	for i := 0; i < len(records); i += nfMaxPerPkt {
		end := i + nfMaxPerPkt
		if end > len(records) {
			end = len(records)
		}
		if err := e.exp.Send(encodeNetFlow(records[i:end])); err != nil {
			return err
		}
	}
	return nil
}

func encodeNetFlow(records []*flow.Record) []byte {
	now := time.Now()
	count := uint16(len(records))
	seq := atomic.AddUint32(&nfSeq, uint32(count)) - uint32(count)
	uptime := uint32(now.Sub(nfStartTime).Milliseconds())

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint16(5))
	binary.Write(buf, binary.BigEndian, count)
	binary.Write(buf, binary.BigEndian, uptime)
	binary.Write(buf, binary.BigEndian, uint32(now.Unix()))
	binary.Write(buf, binary.BigEndian, uint32(now.UnixNano()%1e9))
	binary.Write(buf, binary.BigEndian, seq)
	binary.Write(buf, binary.BigEndian, uint8(0))  // engine type
	binary.Write(buf, binary.BigEndian, uint8(0))  // engine id
	binary.Write(buf, binary.BigEndian, uint16(0)) // sampling interval

	for _, r := range records {
		first := uint32(r.Start.Sub(nfStartTime).Milliseconds())
		last := uint32(r.Last.Sub(nfStartTime).Milliseconds())
		buf.Write(toV4(r.SrcNet()))
		buf.Write(toV4(r.DstNet()))
		buf.Write(net.IPv4zero.To4())                          // nexthop
		binary.Write(buf, binary.BigEndian, uint16(0))        // input
		binary.Write(buf, binary.BigEndian, uint16(0))        // output
		binary.Write(buf, binary.BigEndian, uint32(r.Packets))
		binary.Write(buf, binary.BigEndian, uint32(r.Bytes))
		binary.Write(buf, binary.BigEndian, first)
		binary.Write(buf, binary.BigEndian, last)
		binary.Write(buf, binary.BigEndian, r.FlowKey.SrcPort)
		binary.Write(buf, binary.BigEndian, r.FlowKey.DstPort)
		binary.Write(buf, binary.BigEndian, uint8(0)) // pad1
		binary.Write(buf, binary.BigEndian, r.TCPFlags)
		binary.Write(buf, binary.BigEndian, r.FlowKey.Protocol)
		binary.Write(buf, binary.BigEndian, r.ToS)
		binary.Write(buf, binary.BigEndian, uint16(0)) // src AS
		binary.Write(buf, binary.BigEndian, uint16(0)) // dst AS
		binary.Write(buf, binary.BigEndian, uint8(0))  // src mask
		binary.Write(buf, binary.BigEndian, uint8(0))  // dst mask
		binary.Write(buf, binary.BigEndian, uint16(0)) // pad2
	}
	return buf.Bytes()
}

// ── IPFIX v10 ─────────────────────────────────────────────────────────────────

const (
	ipfixSetIDTemplate = 2
	ipfixBaseTemplateID = 256  // first template ID; increments on each schema change
	ipfixObsDomainID   = 1
	ipfixEnterpriseNum = uint32(0x00001234)
	ipfixChunkSize     = 20
	ipfixRefreshEvery  = 10 * time.Minute // RFC 7011 §8: re-send template periodically
)

// Standard IPFIX information element IDs (IANA, RFC 7012).
const (
	ieOctets    = uint16(1)
	iePackets   = uint16(2)
	ieProto     = uint16(4)
	ieToS       = uint16(5)
	ieTCPFlags  = uint16(6)
	ieSrcPort   = uint16(7)
	ieSrcIPv4   = uint16(8)
	ieDstPort   = uint16(11)
	ieDstIPv4   = uint16(12)
	ieSrcMAC    = uint16(56)  // sourceMacAddress
	ieDstMAC    = uint16(80)  // destinationMacAddress
	ieFlowStart = uint16(152) // flowStartMilliseconds
	ieFlowEnd   = uint16(153) // flowEndMilliseconds
)

// Enterprise field IDs (paired with ipfixEnterpriseNum).
const (
	entSignalStrength   = uint16(1)
	entEncryptionStatus = uint16(2)
	entSensorStatus     = uint16(3) // 0=OK 1=WARNING 2=ERROR derived from IED telemetry
	entCpuLoad          = uint16(4) // agent CPU utilisation 0-100 %
)

// FieldDef describes one IPFIX Information Element, including how to
// encode it from a flow.Record into its wire representation.
type FieldDef struct {
	Name       string // human-readable key used in API calls
	ID         uint16 // IANA IE ID (or enterprise-local ID when Enterprise≠0)
	Len        uint16 // fixed field length in bytes
	Enterprise uint32 // 0 = standard IANA field; non-zero = enterprise PEN
	encode     func(r *flow.Record) []byte
}

// catalog is the complete set of IPFIX fields this agent can export.
// Keys are the names used in API calls (GET/POST /api/ipfix/template).
var catalog map[string]*FieldDef

func init() {
	catalog = map[string]*FieldDef{
		"srcIP": {
			Name: "srcIP", ID: ieSrcIPv4, Len: 4,
			encode: func(r *flow.Record) []byte { return toV4(r.SrcNet()) },
		},
		"dstIP": {
			Name: "dstIP", ID: ieDstIPv4, Len: 4,
			encode: func(r *flow.Record) []byte { return toV4(r.DstNet()) },
		},
		"srcPort": {
			Name: "srcPort", ID: ieSrcPort, Len: 2,
			encode: func(r *flow.Record) []byte { return be16(r.FlowKey.SrcPort) },
		},
		"dstPort": {
			Name: "dstPort", ID: ieDstPort, Len: 2,
			encode: func(r *flow.Record) []byte { return be16(r.FlowKey.DstPort) },
		},
		"proto": {
			Name: "proto", ID: ieProto, Len: 1,
			encode: func(r *flow.Record) []byte { return []byte{r.FlowKey.Protocol} },
		},
		"tos": {
			Name: "tos", ID: ieToS, Len: 1,
			encode: func(r *flow.Record) []byte { return []byte{r.ToS} },
		},
		"tcpFlags": {
			Name: "tcpFlags", ID: ieTCPFlags, Len: 1,
			encode: func(r *flow.Record) []byte { return []byte{r.TCPFlags} },
		},
		"packets": {
			Name: "packets", ID: iePackets, Len: 8,
			encode: func(r *flow.Record) []byte { return be64(r.Packets) },
		},
		"bytes": {
			Name: "bytes", ID: ieOctets, Len: 8,
			encode: func(r *flow.Record) []byte { return be64(r.Bytes) },
		},
		"flowStart": {
			Name: "flowStart", ID: ieFlowStart, Len: 8,
			encode: func(r *flow.Record) []byte { return be64(uint64(r.Start.UnixMilli())) },
		},
		"flowEnd": {
			Name: "flowEnd", ID: ieFlowEnd, Len: 8,
			encode: func(r *flow.Record) []byte { return be64(uint64(r.Last.UnixMilli())) },
		},
		"srcMAC": {
			Name: "srcMAC", ID: ieSrcMAC, Len: 6,
			encode: func(r *flow.Record) []byte { cp := r.SrcMAC; return cp[:] },
		},
		"dstMAC": {
			Name: "dstMAC", ID: ieDstMAC, Len: 6,
			encode: func(r *flow.Record) []byte { cp := r.DstMAC; return cp[:] },
		},
		"signalStrength": {
			Name: "signalStrength", ID: entSignalStrength, Len: 1,
			Enterprise: ipfixEnterpriseNum,
			encode:     func(r *flow.Record) []byte { return []byte{uint8(r.SignalStrength)} },
		},
		"encryptionStatus": {
			Name: "encryptionStatus", ID: entEncryptionStatus, Len: 1,
			Enterprise: ipfixEnterpriseNum,
			encode:     func(r *flow.Record) []byte { return []byte{r.EncryptionStatus} },
		},
		"sensorStatus": {
			Name: "sensorStatus", ID: entSensorStatus, Len: 1,
			Enterprise: ipfixEnterpriseNum,
			// 0=OK  1=WARNING  2=ERROR, derived from IED signal/encryption telemetry.
			encode: func(r *flow.Record) []byte { return []byte{r.SensorStatus} },
		},
		"cpuLoad": {
			Name: "cpuLoad", ID: entCpuLoad, Len: 1,
			Enterprise: ipfixEnterpriseNum,
			// Agent CPU utilisation (0-100 %) sampled from /proc/stat at flow-start.
			encode: func(r *flow.Record) []byte { return []byte{r.CpuLoad} },
		},
	}
}

// DefaultTemplate is the ordered set of fields exported when the agent starts.
var DefaultTemplate = []string{
	"srcIP", "dstIP", "srcPort", "dstPort",
	"proto", "tos", "tcpFlags",
	"packets", "bytes",
	"flowStart", "flowEnd",
	"srcMAC", "dstMAC",
	"signalStrength", "encryptionStatus",
	"sensorStatus", "cpuLoad",
}

var ipfixSeq uint32

// IPFIXEncoder encodes flow records as IPFIX v10 UDP datagrams.
// The active template (field set) can be changed at runtime via SetTemplate.
type IPFIXEncoder struct {
	exp *export.Exporter

	mu         sync.Mutex
	fields     []*FieldDef // ordered active field list
	templateID uint16      // increments on each schema change (256-65534)
	dirty      bool        // true → template record must be sent before next data batch
}

func NewIPFIX(exp *export.Exporter) *IPFIXEncoder {
	enc := &IPFIXEncoder{
		exp:        exp,
		templateID: ipfixBaseTemplateID,
		dirty:      true,
	}
	enc.fields = enc.resolveFields(DefaultTemplate)

	// Periodically mark the template dirty so collectors that restart
	// will receive the template record again (RFC 7011 §8).
	go func() {
		t := time.NewTicker(ipfixRefreshEvery)
		defer t.Stop()
		for range t.C {
			enc.mu.Lock()
			enc.dirty = true
			enc.mu.Unlock()
		}
	}()

	return enc
}

// resolveFields translates a slice of field names into FieldDef pointers,
// silently skipping any unknown names.
func (e *IPFIXEncoder) resolveFields(names []string) []*FieldDef {
	out := make([]*FieldDef, 0, len(names))
	for _, n := range names {
		if f, ok := catalog[n]; ok {
			out = append(out, f)
		}
	}
	return out
}

// SetTemplate replaces the active IPFIX template with the given ordered field
// names. The change takes effect on the next Export call: a new Template Record
// with an incremented template ID is sent before the data.
// Returns an error if any name is absent from the catalog.
func (e *IPFIXEncoder) SetTemplate(names []string) error {
	resolved := make([]*FieldDef, 0, len(names))
	for _, n := range names {
		f, ok := catalog[n]
		if !ok {
			return fmt.Errorf("unknown IPFIX field %q (call GET /api/ipfix/template for available fields)", n)
		}
		resolved = append(resolved, f)
	}
	if len(resolved) == 0 {
		return fmt.Errorf("template must contain at least one field")
	}

	e.mu.Lock()
	e.fields = resolved
	e.templateID++
	if e.templateID < ipfixBaseTemplateID { // guard against uint16 wrap
		e.templateID = ipfixBaseTemplateID
	}
	e.dirty = true
	e.mu.Unlock()
	return nil
}

// CurrentTemplate returns the ordered names of the active fields.
func (e *IPFIXEncoder) CurrentTemplate() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	names := make([]string, len(e.fields))
	for i, f := range e.fields {
		names[i] = f.Name
	}
	return names
}

// AvailableFields returns all field names that can appear in a template,
// sorted alphabetically.
func (e *IPFIXEncoder) AvailableFields() []string {
	names := make([]string, 0, len(catalog))
	for n := range catalog {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Export serialises records using the current template and sends them to the
// collector. A Template Record is prepended whenever the schema has changed.
func (e *IPFIXEncoder) Export(records []*flow.Record) error {
	// Snapshot under lock so we don't hold it during I/O.
	e.mu.Lock()
	fields := e.fields
	tid := e.templateID
	dirty := e.dirty
	e.dirty = false
	e.mu.Unlock()

	if dirty {
		if err := e.exp.Send(e.buildTemplateMsg(fields, tid)); err != nil {
			return err
		}
	}

	for i := 0; i < len(records); i += ipfixChunkSize {
		end := i + ipfixChunkSize
		if end > len(records) {
			end = len(records)
		}
		if err := e.exp.Send(e.buildDataMsg(records[i:end], fields, tid)); err != nil {
			return err
		}
	}
	return nil
}

func ipfixMsgHeader(buf *bytes.Buffer, length uint16) {
	binary.Write(buf, binary.BigEndian, uint16(10)) // IPFIX version
	binary.Write(buf, binary.BigEndian, length)
	binary.Write(buf, binary.BigEndian, uint32(time.Now().Unix()))
	binary.Write(buf, binary.BigEndian, atomic.AddUint32(&ipfixSeq, 1))
	binary.Write(buf, binary.BigEndian, uint32(ipfixObsDomainID))
}

// buildTemplateMsg constructs an IPFIX Template Set message for the given fields.
func (e *IPFIXEncoder) buildTemplateMsg(fields []*FieldDef, tid uint16) []byte {
	body := new(bytes.Buffer)
	binary.Write(body, binary.BigEndian, tid)
	binary.Write(body, binary.BigEndian, uint16(len(fields)))
	for _, f := range fields {
		if f.Enterprise != 0 {
			// Enterprise bit (bit 15) set + 2-byte length + 4-byte PEN
			binary.Write(body, binary.BigEndian, f.ID|0x8000)
			binary.Write(body, binary.BigEndian, f.Len)
			binary.Write(body, binary.BigEndian, f.Enterprise)
		} else {
			binary.Write(body, binary.BigEndian, f.ID)
			binary.Write(body, binary.BigEndian, f.Len)
		}
	}
	// Pad to 4-byte boundary (RFC 7011 §3.3.2)
	for body.Len()%4 != 0 {
		body.WriteByte(0)
	}

	setLen := uint16(4 + body.Len()) // set header (4) + body
	buf := new(bytes.Buffer)
	ipfixMsgHeader(buf, 16+setLen) // msg header (16) + set
	binary.Write(buf, binary.BigEndian, uint16(ipfixSetIDTemplate))
	binary.Write(buf, binary.BigEndian, setLen)
	buf.Write(body.Bytes())
	return buf.Bytes()
}

// buildDataMsg serialises records according to the given field list and
// template ID, producing one IPFIX Data Set message.
func (e *IPFIXEncoder) buildDataMsg(records []*flow.Record, fields []*FieldDef, tid uint16) []byte {
	body := new(bytes.Buffer)
	for _, r := range records {
		for _, f := range fields {
			body.Write(f.encode(r))
		}
	}
	// Pad to 4-byte boundary
	for body.Len()%4 != 0 {
		body.WriteByte(0)
	}

	setLen := uint16(4 + body.Len())
	buf := new(bytes.Buffer)
	ipfixMsgHeader(buf, 16+setLen)
	binary.Write(buf, binary.BigEndian, tid)
	binary.Write(buf, binary.BigEndian, setLen)
	buf.Write(body.Bytes())
	return buf.Bytes()
}

// ── sFlow v5 ──────────────────────────────────────────────────────────────────

var (
	sfSampleSeq uint32
	sfDgSeq     uint32
	sfStart     = time.Now()
)

// SFlowSampler sends sFlow v5 flow-sample datagrams at a 1:rate ratio.
type SFlowSampler struct {
	exp      *export.Exporter
	agentIP  []byte // 4-byte IPv4 of this agent (reported in sFlow datagrams)
	rate     uint32
	counter  uint32
	pool     uint32
}

func NewSFlow(exp *export.Exporter, rate uint32, agentIP net.IP) *SFlowSampler {
	ip := agentIP.To4()
	if ip == nil {
		ip = net.IPv4zero.To4()
	}
	return &SFlowSampler{exp: exp, agentIP: ip, rate: rate}
}

func (s *SFlowSampler) Sample(pkt gopacket.Packet) {
	s.pool++
	s.counter++
	if s.counter < s.rate {
		return
	}
	s.counter = 0

	raw := pkt.Data()
	if len(raw) > 128 {
		raw = raw[:128]
	}
	s.exp.Send(sfDatagram(raw, len(pkt.Data()), s.rate, s.pool, s.agentIP))
}

func sfDatagram(header []byte, frameLen int, rate, pool uint32, agentIP []byte) []byte {
	sample := sfFlowSample(header, frameLen, rate, pool)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(5)) // version
	binary.Write(buf, binary.BigEndian, uint32(1)) // addr type: IPv4
	buf.Write(agentIP)
	binary.Write(buf, binary.BigEndian, uint32(0)) // sub-agent id
	binary.Write(buf, binary.BigEndian, atomic.AddUint32(&sfDgSeq, 1))
	binary.Write(buf, binary.BigEndian, uint32(time.Since(sfStart).Milliseconds()))
	binary.Write(buf, binary.BigEndian, uint32(1)) // num samples
	buf.Write(sample)
	return buf.Bytes()
}

func sfFlowSample(header []byte, frameLen int, rate, pool uint32) []byte {
	record := sfRawHeader(header, frameLen)
	body := new(bytes.Buffer)
	binary.Write(body, binary.BigEndian, atomic.AddUint32(&sfSampleSeq, 1))
	binary.Write(body, binary.BigEndian, uint32(0))          // source id
	binary.Write(body, binary.BigEndian, rate)
	binary.Write(body, binary.BigEndian, pool)
	binary.Write(body, binary.BigEndian, uint32(0))          // drops
	binary.Write(body, binary.BigEndian, uint32(0))          // input ifindex
	binary.Write(body, binary.BigEndian, uint32(0x3FFFFFFF)) // output: multiple
	binary.Write(body, binary.BigEndian, uint32(1))          // num records
	body.Write(record)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(1)) // sample type: flow sample
	binary.Write(buf, binary.BigEndian, uint32(body.Len()))
	buf.Write(body.Bytes())
	return buf.Bytes()
}

func sfRawHeader(header []byte, frameLen int) []byte {
	data := new(bytes.Buffer)
	binary.Write(data, binary.BigEndian, uint32(1))           // Ethernet
	binary.Write(data, binary.BigEndian, uint32(frameLen))
	binary.Write(data, binary.BigEndian, uint32(0))           // stripped
	binary.Write(data, binary.BigEndian, uint32(len(header)))
	data.Write(header)
	for data.Len()%4 != 0 {
		data.WriteByte(0)
	}
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(1)) // raw packet header format
	binary.Write(buf, binary.BigEndian, uint32(data.Len()))
	buf.Write(data.Bytes())
	return buf.Bytes()
}
