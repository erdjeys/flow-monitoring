// Package parser implements UDP listeners and binary decoders for NetFlow v5, IPFIX v10, and sFlow v5.
package parser

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/flowmonitor/collector/influx"
)

// Handler is called for every decoded flow record.
type Handler func(*influx.FlowRecord)

// ── Shared UDP listener ───────────────────────────────────────────────────────

func listen(addr string, parse func([]byte) ([]*influx.FlowRecord, error), h Handler) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	defer pc.Close()

	buf := make([]byte, 65535)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		records, err := parse(buf[:n])
		if err != nil {
			log.Printf("[%s] parse error from %s: %v", addr, src, err)
			continue
		}
		for _, r := range records {
			h(r)
		}
	}
}

// ── NetFlow v5 ────────────────────────────────────────────────────────────────

const (
	nfHeaderSize = 24
	nfRecordSize = 48
)

func ListenNetFlow(addr string, h Handler) error {
	log.Printf("NetFlow v5 listening on %s", addr)
	return listen(addr, parseNetFlow, h)
}

func parseNetFlow(data []byte) ([]*influx.FlowRecord, error) {
	if len(data) < nfHeaderSize {
		return nil, fmt.Errorf("too short: %d bytes", len(data))
	}
	if version := binary.BigEndian.Uint16(data[0:2]); version != 5 {
		return nil, fmt.Errorf("unsupported version %d", version)
	}
	count := int(binary.BigEndian.Uint16(data[2:4]))
	uptime := binary.BigEndian.Uint32(data[4:8])
	exportTime := time.Unix(int64(binary.BigEndian.Uint32(data[8:12])),
		int64(binary.BigEndian.Uint32(data[12:16])))

	if len(data) < nfHeaderSize+count*nfRecordSize {
		return nil, fmt.Errorf("truncated")
	}

	records := make([]*influx.FlowRecord, 0, count)
	for i := 0; i < count; i++ {
		r := data[nfHeaderSize+i*nfRecordSize:]
		first := binary.BigEndian.Uint32(r[24:28])
		last := binary.BigEndian.Uint32(r[28:32])
		startOff := time.Duration(int64(first)-int64(uptime)) * time.Millisecond
		endOff := time.Duration(int64(last)-int64(uptime)) * time.Millisecond

		records = append(records, &influx.FlowRecord{
			Protocol: "netflow5",
			SrcIP:    net.IP(r[0:4]).String(),
			DstIP:    net.IP(r[4:8]).String(),
			SrcPort:  binary.BigEndian.Uint16(r[32:34]),
			DstPort:  binary.BigEndian.Uint16(r[34:36]),
			IPProto:  uint8(r[38]),
			ToS:      uint8(r[39]),
			TCPFlags: uint8(r[37]),
			Packets:  uint64(binary.BigEndian.Uint32(r[16:20])),
			Bytes:    uint64(binary.BigEndian.Uint32(r[20:24])),
			Start:    exportTime.Add(startOff),
			End:      exportTime.Add(endOff),
		})
	}
	return records, nil
}

// ── IPFIX v10 — template-aware parser (RFC 7011) ──────────────────────────────
//
// Unlike NetFlow v5, IPFIX is schema-driven: each Data Set refers to a Template
// that describes the field layout. The sender must transmit Template Records
// (set ID 2) before or alongside the data; the collector learns the schema
// dynamically.  We cache every template we receive and use it to decode
// subsequent Data Records with the matching template ID.

const (
	ipfixSetIDTemplate = 2
	ipfixEnterpriseNum = uint32(0x00001234) // our custom PEN (matches agent)
)

// ipfixField describes one Information Element as declared in a Template Record.
type ipfixField struct {
	id         uint16
	len        uint16
	enterprise uint32 // 0 = standard IANA field
}

// ipfixTmpl holds the ordered field list learned from a received Template Record.
type ipfixTmpl struct {
	fields    []ipfixField
	recordLen int // precomputed byte length of one data record
}

// IPFIXListener is a stateful IPFIX listener.  It maintains a per-instance
// template cache so that template records received in one datagram are
// applied when decoding data records in subsequent datagrams.
type IPFIXListener struct {
	mu        sync.RWMutex
	templates map[uint16]*ipfixTmpl // key = templateID
}

func NewIPFIXListener() *IPFIXListener {
	return &IPFIXListener{templates: make(map[uint16]*ipfixTmpl)}
}

func ListenIPFIX(addr string, h Handler) error {
	return NewIPFIXListener().Listen(addr, h)
}

func (l *IPFIXListener) Listen(addr string, h Handler) error {
	log.Printf("IPFIX listening on %s", addr)
	return listen(addr, l.parse, h)
}

func (l *IPFIXListener) parse(data []byte) ([]*influx.FlowRecord, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("too short")
	}
	if version := binary.BigEndian.Uint16(data[0:2]); version != 10 {
		return nil, fmt.Errorf("not IPFIX (version %d)", version)
	}
	totalLen := int(binary.BigEndian.Uint16(data[2:4]))
	if len(data) < totalLen {
		return nil, fmt.Errorf("truncated")
	}

	// Two-pass: first absorb Template Sets so they are available when
	// we decode Data Sets later in the same message.
	for pos := 16; pos+4 <= totalLen; {
		setID := binary.BigEndian.Uint16(data[pos : pos+2])
		setLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		if setLen < 4 || pos+setLen > totalLen {
			break
		}
		if setID == ipfixSetIDTemplate {
			l.parseTemplateSets(data[pos+4 : pos+setLen])
		}
		pos += setLen
	}

	// Second pass: decode Data Sets using the now-populated cache.
	var records []*influx.FlowRecord
	for pos := 16; pos+4 <= totalLen; {
		setID := binary.BigEndian.Uint16(data[pos : pos+2])
		setLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		if setLen < 4 || pos+setLen > totalLen {
			break
		}
		if setID >= 256 { // Data Set (template ID ≥ 256 per RFC 7011 §3.4.3)
			l.mu.RLock()
			tmpl, ok := l.templates[setID]
			l.mu.RUnlock()
			if ok && tmpl.recordLen > 0 {
				payload := data[pos+4 : pos+setLen]
				for i := 0; i+tmpl.recordLen <= len(payload); i += tmpl.recordLen {
					if r := decodeIPFIXRecord(payload[i:i+tmpl.recordLen], tmpl); r != nil {
						records = append(records, r)
					}
				}
			}
		}
		pos += setLen
	}
	return records, nil
}

// parseTemplateSets processes one Template Set payload (bytes after the set header).
// Each Template Record inside may define a new template or update an existing one.
func (l *IPFIXListener) parseTemplateSets(payload []byte) {
	pos := 0
	for pos+4 <= len(payload) {
		tid := binary.BigEndian.Uint16(payload[pos : pos+2])
		fcount := int(binary.BigEndian.Uint16(payload[pos+2 : pos+4]))
		pos += 4

		if fcount == 0 {
			// Template withdrawal (RFC 7011 §8.1) — remove from cache.
			l.mu.Lock()
			delete(l.templates, tid)
			l.mu.Unlock()
			continue
		}

		fields := make([]ipfixField, 0, fcount)
		recLen := 0
		for i := 0; i < fcount; i++ {
			if pos+4 > len(payload) {
				break
			}
			fid := binary.BigEndian.Uint16(payload[pos : pos+2])
			flen := binary.BigEndian.Uint16(payload[pos+2 : pos+4])
			pos += 4

			var ent uint32
			if fid&0x8000 != 0 { // enterprise bit set
				fid &^= 0x8000
				if pos+4 <= len(payload) {
					ent = binary.BigEndian.Uint32(payload[pos : pos+4])
					pos += 4
				}
			}
			fields = append(fields, ipfixField{id: fid, len: flen, enterprise: ent})
			recLen += int(flen)
		}

		l.mu.Lock()
		l.templates[tid] = &ipfixTmpl{fields: fields, recordLen: recLen}
		l.mu.Unlock()
		log.Printf("[IPFIX] template %d: %d fields, %d bytes/record", tid, len(fields), recLen)
	}
}

// decodeIPFIXRecord maps raw field bytes to a FlowRecord using the given template.
// Unknown fields are skipped (their bytes are consumed but ignored).
func decodeIPFIXRecord(data []byte, tmpl *ipfixTmpl) *influx.FlowRecord {
	r := &influx.FlowRecord{Protocol: "ipfix"}
	pos := 0
	for _, f := range tmpl.fields {
		end := pos + int(f.len)
		if end > len(data) {
			break
		}
		val := data[pos:end]
		pos = end

		if f.enterprise == 0 {
			// Standard IANA IEs (RFC 7012).
			switch f.id {
			case 8: // sourceIPv4Address
				r.SrcIP = net.IP(val).String()
			case 12: // destinationIPv4Address
				r.DstIP = net.IP(val).String()
			case 7: // sourceTransportPort
				r.SrcPort = binary.BigEndian.Uint16(val)
			case 11: // destinationTransportPort
				r.DstPort = binary.BigEndian.Uint16(val)
			case 4: // protocolIdentifier
				r.IPProto = val[0]
			case 5: // ipClassOfService
				r.ToS = val[0]
			case 6: // tcpControlBits
				r.TCPFlags = val[0]
			case 2: // packetDeltaCount
				r.Packets = beUint(val)
			case 1: // octetDeltaCount
				r.Bytes = beUint(val)
			case 152: // flowStartMilliseconds
				r.Start = time.UnixMilli(int64(beUint(val)))
			case 153: // flowEndMilliseconds
				r.End = time.UnixMilli(int64(beUint(val)))
			case 56: // sourceMacAddress
				r.SrcMAC = fmtMAC(val)
			case 80: // destinationMacAddress
				r.DstMAC = fmtMAC(val)
			}
		} else if f.enterprise == ipfixEnterpriseNum {
			// Custom enterprise IEs (PEN 0x1234, defined in agent/protocols).
			switch f.id {
			case 1: // signalStrength
				r.SignalStrength = int8(val[0])
			case 2: // encryptionStatus
				r.EncryptionStatus = val[0]
			case 3: // sensorStatus
				r.SensorStatus = val[0]
			case 4: // cpuLoad
				r.CpuLoad = val[0]
			}
		}
		// All other enterprise IDs: bytes already consumed, silently skipped.
	}
	return r
}

// beUint decodes a big-endian unsigned integer of 1–8 bytes.
func beUint(b []byte) uint64 {
	var v uint64
	for _, byt := range b {
		v = v<<8 | uint64(byt)
	}
	return v
}

func fmtMAC(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		b[0], b[1], b[2], b[3], b[4], b[5])
}

// ── sFlow v5 ──────────────────────────────────────────────────────────────────

func ListenSFlow(addr string, h Handler) error {
	log.Printf("sFlow listening on %s", addr)
	return listen(addr, parseSFlow, h)
}

func parseSFlow(data []byte) ([]*influx.FlowRecord, error) {
	if len(data) < 28 {
		return nil, fmt.Errorf("too short")
	}
	if v := binary.BigEndian.Uint32(data[0:4]); v != 5 {
		return nil, fmt.Errorf("unsupported sFlow version %d", v)
	}
	numSamples := binary.BigEndian.Uint32(data[24:28])

	var records []*influx.FlowRecord
	for pos, i := 28, uint32(0); i < numSamples; i++ {
		if pos+8 > len(data) {
			break
		}
		sampleType := binary.BigEndian.Uint32(data[pos : pos+4])
		sampleLen := int(binary.BigEndian.Uint32(data[pos+4 : pos+8]))
		pos += 8
		if pos+sampleLen > len(data) {
			break
		}
		if sampleType == 1 {
			records = append(records, parseFlowSample(data[pos:pos+sampleLen])...)
		}
		pos += sampleLen
	}
	return records, nil
}

func parseFlowSample(data []byte) []*influx.FlowRecord {
	if len(data) < 32 {
		return nil
	}
	samplingRate := binary.BigEndian.Uint32(data[8:12])
	numRecords := binary.BigEndian.Uint32(data[28:32])

	var records []*influx.FlowRecord
	for pos, i := 32, uint32(0); i < numRecords; i++ {
		if pos+8 > len(data) {
			break
		}
		recFormat := binary.BigEndian.Uint32(data[pos : pos+4])
		recLen := int(binary.BigEndian.Uint32(data[pos+4 : pos+8]))
		pos += 8
		if pos+recLen > len(data) {
			break
		}
		if recFormat == 1 {
			if r := parseRawHeader(data[pos:pos+recLen], samplingRate); r != nil {
				records = append(records, r)
			}
		}
		pos += recLen
	}
	return records
}

func parseRawHeader(data []byte, samplingRate uint32) *influx.FlowRecord {
	if len(data) < 16 {
		return nil
	}
	headerLen := int(binary.BigEndian.Uint32(data[12:16]))
	if 16+headerLen > len(data) {
		return nil
	}
	header := data[16 : 16+headerLen]
	frameLen := binary.BigEndian.Uint32(data[4:8])

	rec := &influx.FlowRecord{
		Protocol: "sflow5",
		Bytes:    uint64(frameLen) * uint64(samplingRate),
		Packets:  uint64(samplingRate),
		Start:    time.Now(),
		End:      time.Now(),
	}

	// Ethernet (14B) → IPv4.
	if len(header) < 34 {
		return rec
	}
	rec.SrcMAC = fmtMAC(header[6:12])
	rec.DstMAC = fmtMAC(header[0:6])

	ip := header[14:]
	if ip[0]>>4 != 4 {
		return rec
	}
	rec.SrcIP = net.IP(ip[12:16]).String()
	rec.DstIP = net.IP(ip[16:20]).String()
	rec.IPProto = ip[9]
	rec.ToS = ip[1]

	ihl := int(ip[0]&0x0f) * 4
	if len(ip) >= ihl+4 {
		t := ip[ihl:]
		rec.SrcPort = binary.BigEndian.Uint16(t[0:2])
		rec.DstPort = binary.BigEndian.Uint16(t[2:4])
		if rec.IPProto == 6 && len(t) >= 14 {
			rec.TCPFlags = t[13]
		}
	}
	return rec
}
