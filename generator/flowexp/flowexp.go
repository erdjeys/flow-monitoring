// Package flowexp sends synthetic NetFlow v5 records to a collector over UDP.
// The generator uses this so the collector receives flow data for all traffic
// the generator produces, regardless of whether the agent can see it on the wire.
package flowexp

import (
	"encoding/binary"
	"log"
	"net"
	"sync/atomic"
	"time"
)

// Record describes a single network flow to be exported.
type Record struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8 // 6=TCP 17=UDP 1=ICMP
	TCPFlags uint8
	Packets  uint32
	Bytes    uint32
}

// Exporter sends NetFlow v5 UDP packets to a collector.
type Exporter struct {
	conn  *net.UDPConn
	seq   uint32
	start time.Time
}

func New(addr string) (*Exporter, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, err
	}
	return &Exporter{conn: conn, start: time.Now()}, nil
}

func (e *Exporter) Close() { e.conn.Close() }

// Send exports records in batches of up to 30 (NetFlow v5 practical limit).
func (e *Exporter) Send(records []Record) {
	if e == nil || len(records) == 0 {
		return
	}
	const max = 30
	for i := 0; i < len(records); i += max {
		end := i + max
		if end > len(records) {
			end = len(records)
		}
		e.sendBatch(records[i:end])
	}
}

func (e *Exporter) sendBatch(records []Record) {
	n := len(records)
	buf := make([]byte, 24+n*48)
	now := time.Now()
	uptime := uint32(now.Sub(e.start).Milliseconds())
	seq := atomic.AddUint32(&e.seq, uint32(n))

	// NetFlow v5 header (24 bytes)
	binary.BigEndian.PutUint16(buf[0:], 5)
	binary.BigEndian.PutUint16(buf[2:], uint16(n))
	binary.BigEndian.PutUint32(buf[4:], uptime)
	binary.BigEndian.PutUint32(buf[8:], uint32(now.Unix()))
	binary.BigEndian.PutUint32(buf[12:], uint32(now.Nanosecond()))
	binary.BigEndian.PutUint32(buf[16:], seq)

	// Per-record fields (48 bytes each)
	for i, r := range records {
		off := 24 + i*48
		src := r.SrcIP.To4()
		if src == nil {
			src = net.IPv4zero.To4()
		}
		dst := r.DstIP.To4()
		if dst == nil {
			dst = net.IPv4zero.To4()
		}
		copy(buf[off:], src)                                 // srcaddr [4]
		copy(buf[off+4:], dst)                               // dstaddr [4]
		// off+8:  nexthop  [4] — zero
		// off+12: input    [2] — zero
		// off+14: output   [2] — zero
		binary.BigEndian.PutUint32(buf[off+16:], r.Packets) // dPkts
		binary.BigEndian.PutUint32(buf[off+20:], r.Bytes)   // dOctets
		binary.BigEndian.PutUint32(buf[off+24:], uptime)    // first (flow start = now)
		// Give each record a unique end timestamp (+i ms) so InfluxDB doesn't
		// deduplicate records that share the same tag set within a batch.
		binary.BigEndian.PutUint32(buf[off+28:], uptime+uint32(i)) // last
		binary.BigEndian.PutUint16(buf[off+32:], r.SrcPort)
		binary.BigEndian.PutUint16(buf[off+34:], r.DstPort)
		// off+36: pad
		buf[off+37] = r.TCPFlags
		buf[off+38] = r.Protocol
		// off+39: ToS, off+40+: AS/mask — zeros
	}

	if _, err := e.conn.Write(buf); err != nil {
		log.Printf("flowexp send: %v", err)
	}
}
