// Protocol wire-format compliance tests.
//
// Every exported datagram is verified byte-by-byte against the relevant RFC:
//   NetFlow v5  — RFC 3954
//   IPFIX v10   — RFC 7011
//   sFlow v5    — sFlow v5 specification (Peter Phaal, 2004)
//
// Tests run with: go test ./protocols/... -v
package protocols

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/flowmonitor/agent/export"
	"github.com/flowmonitor/agent/flow"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

// listenUDP opens a UDP server on a random loopback port.
// Every received datagram is forwarded to the returned channel.
// The listener is closed automatically when the test finishes.
func listenUDP(t *testing.T) (addr string, packets <-chan []byte) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listenUDP: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	ch := make(chan []byte, 64)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			ch <- pkt
		}
	}()
	return pc.LocalAddr().String(), ch
}

// newExporter creates an Exporter aimed at the given local UDP address.
func newExporter(t *testing.T, addr string) *export.Exporter {
	t.Helper()
	exp, err := export.New(addr)
	if err != nil {
		t.Fatalf("export.New(%s): %v", addr, err)
	}
	t.Cleanup(func() { exp.Close() })
	return exp
}

// makeRecord builds a flow.Record from readable fields.
func makeRecord(srcIP, dstIP string, srcPort, dstPort uint16, proto uint8) *flow.Record {
	r := &flow.Record{
		Packets:  10,
		Bytes:    1500,
		Start:    time.Now().Add(-5 * time.Second),
		Last:     time.Now(),
		TCPFlags: 0x12,
	}
	copy(r.FlowKey.SrcIP[:], net.ParseIP(srcIP).To4())
	copy(r.FlowKey.DstIP[:], net.ParseIP(dstIP).To4())
	r.FlowKey.SrcPort = srcPort
	r.FlowKey.DstPort = dstPort
	r.FlowKey.Protocol = proto
	return r
}

// recv reads one datagram from the channel, failing the test on timeout.
func recv(t *testing.T, ch <-chan []byte) []byte {
	t.Helper()
	select {
	case pkt := <-ch:
		return pkt
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for UDP datagram")
		return nil
	}
}

// expectNoMore asserts that no further datagrams arrive within 100 ms.
func expectNoMore(t *testing.T, ch <-chan []byte) {
	t.Helper()
	select {
	case extra := <-ch:
		setID := binary.BigEndian.Uint16(extra[16:18])
		t.Errorf("unexpected extra datagram (set ID = %d)", setID)
	case <-time.After(100 * time.Millisecond):
		// OK
	}
}

// ── NetFlow v5 — RFC 3954 ─────────────────────────────────────────────────────

// RFC 3954 §5: Version field at bytes [0:2] must equal 5.
func TestNetFlow_RFC3954_Version(t *testing.T) {
	addr, pkts := listenUDP(t)
	enc := NewNetFlow(newExporter(t, addr))
	enc.Export([]*flow.Record{makeRecord("1.2.3.4", "5.6.7.8", 1234, 80, 6)})
	pkt := recv(t, pkts)
	if got := binary.BigEndian.Uint16(pkt[0:2]); got != 5 {
		t.Errorf("NetFlow version = %d, want 5 (RFC 3954 §5)", got)
	}
}

// RFC 3954 §5: Count field at bytes [2:4] must equal the number of flow records.
func TestNetFlow_RFC3954_Count(t *testing.T) {
	addr, pkts := listenUDP(t)
	enc := NewNetFlow(newExporter(t, addr))
	records := []*flow.Record{
		makeRecord("1.2.3.4", "5.6.7.8", 1000, 80, 6),
		makeRecord("1.2.3.5", "5.6.7.9", 1001, 443, 6),
		makeRecord("1.2.3.6", "5.6.7.10", 1002, 53, 17),
	}
	enc.Export(records)
	pkt := recv(t, pkts)
	if got := binary.BigEndian.Uint16(pkt[2:4]); got != uint16(len(records)) {
		t.Errorf("NetFlow count = %d, want %d", got, len(records))
	}
}

// RFC 3954 §5: total datagram size must be exactly 24 (header) + n×48 (records).
func TestNetFlow_RFC3954_PacketSize(t *testing.T) {
	addr, pkts := listenUDP(t)
	enc := NewNetFlow(newExporter(t, addr))
	const n = 5
	records := make([]*flow.Record, n)
	for i := range records {
		records[i] = makeRecord("1.2.3.4", "5.6.7.8", uint16(1000+i), 80, 6)
	}
	enc.Export(records)
	pkt := recv(t, pkts)
	want := 24 + n*48
	if len(pkt) != want {
		t.Errorf("NetFlow datagram size = %d, want %d (24 + %d×48)", len(pkt), want, n)
	}
}

// RFC 3954 §5: srcaddr at record[0:4] and dstaddr at record[4:8].
func TestNetFlow_RFC3954_IPAddresses(t *testing.T) {
	addr, pkts := listenUDP(t)
	enc := NewNetFlow(newExporter(t, addr))
	enc.Export([]*flow.Record{makeRecord("192.168.1.1", "10.0.0.1", 5000, 443, 6)})
	pkt := recv(t, pkts)
	rec := pkt[24:] // first flow record starts after 24-byte header
	if !net.IP(rec[0:4]).Equal(net.ParseIP("192.168.1.1").To4()) {
		t.Errorf("srcIP = %v, want 192.168.1.1", net.IP(rec[0:4]))
	}
	if !net.IP(rec[4:8]).Equal(net.ParseIP("10.0.0.1").To4()) {
		t.Errorf("dstIP = %v, want 10.0.0.1", net.IP(rec[4:8]))
	}
}

// RFC 3954 §5: srcport at record[32:34], dstport at record[34:36].
func TestNetFlow_RFC3954_Ports(t *testing.T) {
	addr, pkts := listenUDP(t)
	enc := NewNetFlow(newExporter(t, addr))
	enc.Export([]*flow.Record{makeRecord("1.2.3.4", "5.6.7.8", 12345, 443, 6)})
	pkt := recv(t, pkts)
	rec := pkt[24:]
	srcPort := binary.BigEndian.Uint16(rec[32:34])
	dstPort := binary.BigEndian.Uint16(rec[34:36])
	if srcPort != 12345 {
		t.Errorf("srcPort = %d, want 12345", srcPort)
	}
	if dstPort != 443 {
		t.Errorf("dstPort = %d, want 443", dstPort)
	}
}

// RFC 3954 §5: prot (IP protocol) at record[38].
func TestNetFlow_RFC3954_Protocol(t *testing.T) {
	addr, pkts := listenUDP(t)
	enc := NewNetFlow(newExporter(t, addr))
	enc.Export([]*flow.Record{makeRecord("1.2.3.4", "5.6.7.8", 1234, 53, 17)}) // UDP = 17
	pkt := recv(t, pkts)
	if got := pkt[24+38]; got != 17 {
		t.Errorf("prot = %d, want 17 (UDP)", got)
	}
}

// RFC 3954 §5: dPkts at record[16:20], dOctets at record[20:24].
func TestNetFlow_RFC3954_Counters(t *testing.T) {
	addr, pkts := listenUDP(t)
	enc := NewNetFlow(newExporter(t, addr))
	r := makeRecord("1.2.3.4", "5.6.7.8", 1234, 80, 6)
	r.Packets = 42
	r.Bytes = 9000
	enc.Export([]*flow.Record{r})
	pkt := recv(t, pkts)
	rec := pkt[24:]
	if got := binary.BigEndian.Uint32(rec[16:20]); got != 42 {
		t.Errorf("dPkts = %d, want 42", got)
	}
	if got := binary.BigEndian.Uint32(rec[20:24]); got != 9000 {
		t.Errorf("dOctets = %d, want 9000", got)
	}
}

// RFC 3954 §5: tcp_flags at record[37] must preserve all flag bits.
func TestNetFlow_RFC3954_TCPFlags(t *testing.T) {
	addr, pkts := listenUDP(t)
	enc := NewNetFlow(newExporter(t, addr))
	r := makeRecord("1.2.3.4", "5.6.7.8", 1234, 80, 6)
	r.TCPFlags = 0x1B // SYN+FIN+ACK+PSH
	enc.Export([]*flow.Record{r})
	pkt := recv(t, pkts)
	if got := pkt[24+37]; got != 0x1B {
		t.Errorf("tcp_flags = 0x%02X, want 0x1B", got)
	}
}

// RFC 3954 §6: batches of more than 30 records must be split across
// multiple datagrams with at most 30 records each.
func TestNetFlow_RFC3954_BatchSplit(t *testing.T) {
	addr, pkts := listenUDP(t)
	enc := NewNetFlow(newExporter(t, addr))
	const n = 35 // nfMaxPerPkt = 30, so expect 2 datagrams: 30 + 5
	records := make([]*flow.Record, n)
	for i := range records {
		records[i] = makeRecord("1.2.3.4", "5.6.7.8", uint16(1000+i), 80, 6)
	}
	enc.Export(records)
	pkt1 := recv(t, pkts)
	pkt2 := recv(t, pkts)
	c1 := int(binary.BigEndian.Uint16(pkt1[2:4]))
	c2 := int(binary.BigEndian.Uint16(pkt2[2:4]))
	if c1 != 30 {
		t.Errorf("first datagram count = %d, want 30", c1)
	}
	if c2 != n-30 {
		t.Errorf("second datagram count = %d, want %d", c2, n-30)
	}
}

// ── IPFIX v10 — RFC 7011 ──────────────────────────────────────────────────────

// RFC 7011 §3.1: Version field at message[0:2] must equal 10.
func TestIPFIX_RFC7011_Version(t *testing.T) {
	addr, pkts := listenUDP(t)
	enc := NewIPFIX(newExporter(t, addr))
	enc.Export([]*flow.Record{makeRecord("1.2.3.4", "5.6.7.8", 1234, 80, 6)})
	pkt := recv(t, pkts) // first packet is the template
	if got := binary.BigEndian.Uint16(pkt[0:2]); got != 10 {
		t.Errorf("IPFIX version = %d, want 10 (RFC 7011 §3.1)", got)
	}
}

// RFC 7011 §3.1: Length field at message[2:4] must equal total message bytes.
func TestIPFIX_RFC7011_LengthField(t *testing.T) {
	addr, pkts := listenUDP(t)
	enc := NewIPFIX(newExporter(t, addr))
	enc.Export([]*flow.Record{makeRecord("1.2.3.4", "5.6.7.8", 1234, 80, 6)})
	for i, name := range []string{"template", "data"} {
		pkt := recv(t, pkts)
		declared := int(binary.BigEndian.Uint16(pkt[2:4]))
		if declared != len(pkt) {
			t.Errorf("%s packet: declared length %d ≠ actual length %d", name, declared, len(pkt))
		}
		_ = i
	}
}

// RFC 7011 §3.4.1: Template Set must use Set ID = 2.
func TestIPFIX_RFC7011_TemplateSetID(t *testing.T) {
	addr, pkts := listenUDP(t)
	enc := NewIPFIX(newExporter(t, addr))
	enc.Export([]*flow.Record{makeRecord("1.2.3.4", "5.6.7.8", 1234, 80, 6)})
	tpl := recv(t, pkts)
	// IPFIX message header is 16 bytes; Set header follows at [16:20].
	if setID := binary.BigEndian.Uint16(tpl[16:18]); setID != 2 {
		t.Errorf("template set ID = %d, want 2 (RFC 7011 §3.4.1)", setID)
	}
}

// RFC 7011 §3.4.1: Template ID must be ≥ 256.
func TestIPFIX_RFC7011_TemplateIDRange(t *testing.T) {
	addr, pkts := listenUDP(t)
	enc := NewIPFIX(newExporter(t, addr))
	enc.Export([]*flow.Record{makeRecord("1.2.3.4", "5.6.7.8", 1234, 80, 6)})
	tpl := recv(t, pkts)
	// Template record starts at offset 20 (16 msg + 4 set headers).
	tplID := binary.BigEndian.Uint16(tpl[20:22])
	if tplID < 256 {
		t.Errorf("template ID = %d, must be ≥ 256 (RFC 7011 §3.4.1)", tplID)
	}
}

// RFC 7011 §3.3.2: Set body must be padded to a 4-byte boundary.
func TestIPFIX_RFC7011_FourByteAlignment(t *testing.T) {
	addr, pkts := listenUDP(t)
	enc := NewIPFIX(newExporter(t, addr))
	enc.Export([]*flow.Record{makeRecord("1.2.3.4", "5.6.7.8", 1234, 80, 6)})
	for _, name := range []string{"template", "data"} {
		pkt := recv(t, pkts)
		setLen := int(binary.BigEndian.Uint16(pkt[18:20]))
		if setLen%4 != 0 {
			t.Errorf("%s: set length %d is not 4-byte aligned (RFC 7011 §3.3.2)", name, setLen)
		}
	}
}

// RFC 7011 §3.4.3: Data Set ID must equal the associated template ID.
func TestIPFIX_RFC7011_DataSetIDMatchesTemplate(t *testing.T) {
	addr, pkts := listenUDP(t)
	enc := NewIPFIX(newExporter(t, addr))
	enc.Export([]*flow.Record{makeRecord("1.2.3.4", "5.6.7.8", 1234, 80, 6)})
	tpl := recv(t, pkts)
	data := recv(t, pkts)
	tplID := binary.BigEndian.Uint16(tpl[20:22])
	dataSetID := binary.BigEndian.Uint16(data[16:18])
	if dataSetID != tplID {
		t.Errorf("data set ID %d ≠ template ID %d", dataSetID, tplID)
	}
}

// RFC 7011 §6.2: enterprise fields must have bit 15 set in the field specifier,
// followed by a 4-byte Private Enterprise Number (PEN = 0x00001234).
func TestIPFIX_RFC7011_EnterpriseFieldEncoding(t *testing.T) {
	addr, pkts := listenUDP(t)
	enc := NewIPFIX(newExporter(t, addr))
	// Use a template containing only the enterprise cpuLoad field so the
	// first field specifier in the template is guaranteed to be enterprise.
	if err := enc.SetTemplate([]string{"cpuLoad"}); err != nil {
		t.Fatalf("SetTemplate: %v", err)
	}
	enc.Export([]*flow.Record{makeRecord("1.2.3.4", "5.6.7.8", 1234, 80, 6)})

	tpl := recv(t, pkts) // template packet

	setID := binary.BigEndian.Uint16(tpl[16:18])
	if setID != 2 {
		t.Fatalf("expected template set (ID=2), got %d", setID)
	}
	// Offsets inside the template packet:
	//   [16:18] set ID
	//   [18:20] set length
	//   [20:22] template ID
	//   [22:24] field count
	//   [24:26] first field specifier (should have enterprise bit set)
	//   [26:28] field length
	//   [28:32] PEN (only for enterprise fields)
	fieldSpec := binary.BigEndian.Uint16(tpl[24:26])
	if fieldSpec&0x8000 == 0 {
		t.Errorf("enterprise field 'cpuLoad' missing enterprise bit (bit 15): specifier=0x%04X (RFC 7011 §6.2)", fieldSpec)
	}
	pen := binary.BigEndian.Uint32(tpl[28:32])
	const wantPEN = uint32(0x00001234)
	if pen != wantPEN {
		t.Errorf("PEN = 0x%08X, want 0x%08X", pen, wantPEN)
	}
}

// RFC 7011 §8: on a fresh encoder, the template MUST precede the first data set.
func TestIPFIX_RFC7011_TemplateBeforeData(t *testing.T) {
	addr, pkts := listenUDP(t)
	enc := NewIPFIX(newExporter(t, addr))
	enc.Export([]*flow.Record{makeRecord("1.2.3.4", "5.6.7.8", 1234, 80, 6)})

	first := recv(t, pkts)
	if setID := binary.BigEndian.Uint16(first[16:18]); setID != 2 {
		t.Errorf("first datagram set ID = %d; must be template (2) before any data (RFC 7011 §8)", setID)
	}
	second := recv(t, pkts)
	if setID := binary.BigEndian.Uint16(second[16:18]); setID < 256 {
		t.Errorf("second datagram set ID = %d; expected data (≥256)", setID)
	}
}

// RFC 7011 §8: SetTemplate must cause a new template with a higher ID
// to be transmitted before the next data set.
func TestIPFIX_RFC7011_TemplateRefreshOnSchemaChange(t *testing.T) {
	addr, pkts := listenUDP(t)
	enc := NewIPFIX(newExporter(t, addr))

	enc.Export([]*flow.Record{makeRecord("1.2.3.4", "5.6.7.8", 1234, 80, 6)})
	tpl1 := recv(t, pkts)
	recv(t, pkts) // consume data
	tplID1 := binary.BigEndian.Uint16(tpl1[20:22])

	enc.SetTemplate([]string{"srcIP", "dstIP", "bytes"})
	enc.Export([]*flow.Record{makeRecord("1.2.3.4", "5.6.7.8", 1234, 80, 6)})
	tpl2 := recv(t, pkts)
	recv(t, pkts) // consume data

	if setID := binary.BigEndian.Uint16(tpl2[16:18]); setID != 2 {
		t.Errorf("after SetTemplate: first datagram set ID = %d, want 2 (template)", setID)
	}
	tplID2 := binary.BigEndian.Uint16(tpl2[20:22])
	if tplID2 <= tplID1 {
		t.Errorf("template ID must increment on schema change: before=%d after=%d", tplID1, tplID2)
	}
}

// Successive Export calls without schema changes must NOT resend the template.
func TestIPFIX_NoRedundantTemplate(t *testing.T) {
	addr, pkts := listenUDP(t)
	enc := NewIPFIX(newExporter(t, addr))

	enc.Export([]*flow.Record{makeRecord("1.2.3.4", "5.6.7.8", 1234, 80, 6)})
	recv(t, pkts) // initial template
	recv(t, pkts) // initial data

	enc.Export([]*flow.Record{makeRecord("1.2.3.4", "5.6.7.8", 1234, 80, 6)})
	data := recv(t, pkts)
	if setID := binary.BigEndian.Uint16(data[16:18]); setID == 2 {
		t.Errorf("unexpected template retransmission on second Export call (set ID=2)")
	}
	expectNoMore(t, pkts)
}

// SetTemplate must reject unknown field names.
func TestIPFIX_SetTemplate_UnknownField(t *testing.T) {
	addr, _ := listenUDP(t)
	enc := NewIPFIX(newExporter(t, addr))
	if err := enc.SetTemplate([]string{"srcIP", "unknownField"}); err == nil {
		t.Error("SetTemplate with unknown field must return error")
	}
}

// SetTemplate must reject an empty field list.
func TestIPFIX_SetTemplate_EmptyList(t *testing.T) {
	addr, _ := listenUDP(t)
	enc := NewIPFIX(newExporter(t, addr))
	if err := enc.SetTemplate([]string{}); err == nil {
		t.Error("SetTemplate with empty list must return error")
	}
}

// AvailableFields must include all expected catalog entries.
func TestIPFIX_AvailableFields(t *testing.T) {
	addr, _ := listenUDP(t)
	enc := NewIPFIX(newExporter(t, addr))
	fields := enc.AvailableFields()
	required := []string{
		"bytes", "cpuLoad", "dstIP", "dstMAC", "dstPort",
		"encryptionStatus", "flowEnd", "flowStart",
		"packets", "proto", "sensorStatus", "signalStrength",
		"srcIP", "srcMAC", "srcPort", "tcpFlags", "tos",
	}
	got := make(map[string]bool, len(fields))
	for _, f := range fields {
		got[f] = true
	}
	for _, want := range required {
		if !got[want] {
			t.Errorf("AvailableFields missing %q", want)
		}
	}
}

// Large batch of records must be split into multiple IPFIX datagrams of
// at most ipfixChunkSize (20) records each.
func TestIPFIX_BatchChunking(t *testing.T) {
	addr, pkts := listenUDP(t)
	enc := NewIPFIX(newExporter(t, addr))

	const n = 45 // 45 records → ceil(45/20) = 3 data datagrams
	records := make([]*flow.Record, n)
	for i := range records {
		records[i] = makeRecord("1.2.3.4", "5.6.7.8", uint16(1000+i), 80, 6)
	}
	enc.Export(records)

	recv(t, pkts) // template
	dataCount := 0
	deadline := time.After(2 * time.Second)
loop:
	for {
		select {
		case pkt := <-pkts:
			if binary.BigEndian.Uint16(pkt[16:18]) >= 256 {
				dataCount++
			}
		case <-deadline:
			break loop
		}
	}
	if dataCount != 3 {
		t.Errorf("expected 3 data datagrams for %d records (chunkSize=20), got %d", n, dataCount)
	}
}

// ── sFlow v5 ──────────────────────────────────────────────────────────────────

// sFlow v5 §4: datagram version field [0:4] must be 5.
func TestSFlow_Version(t *testing.T) {
	addr, pkts := listenUDP(t)
	s := NewSFlow(newExporter(t, addr), 1, net.ParseIP("10.0.0.1").To4())
	s.Sample(rawPacket())
	dgram := recv(t, pkts)
	if v := binary.BigEndian.Uint32(dgram[0:4]); v != 5 {
		t.Errorf("sFlow version = %d, want 5", v)
	}
}

// sFlow v5 §4: agent address type [4:8] must be 1 (IPv4).
func TestSFlow_AgentAddressType(t *testing.T) {
	addr, pkts := listenUDP(t)
	s := NewSFlow(newExporter(t, addr), 1, net.ParseIP("10.0.0.1").To4())
	s.Sample(rawPacket())
	dgram := recv(t, pkts)
	if at := binary.BigEndian.Uint32(dgram[4:8]); at != 1 {
		t.Errorf("sFlow agent address type = %d, want 1 (IPv4)", at)
	}
}

// sFlow v5 §4: agent IPv4 address [8:12] must match the IP passed to NewSFlow.
func TestSFlow_AgentIP(t *testing.T) {
	addr, pkts := listenUDP(t)
	agentIP := net.ParseIP("10.0.2.20").To4()
	s := NewSFlow(newExporter(t, addr), 1, agentIP)
	s.Sample(rawPacket())
	dgram := recv(t, pkts)
	if !net.IP(dgram[8:12]).Equal(agentIP) {
		t.Errorf("sFlow agent IP = %v, want %v", net.IP(dgram[8:12]), agentIP)
	}
}

// sFlow v5: with rate=N exactly one datagram must be sent per N packets.
func TestSFlow_SamplingRate(t *testing.T) {
	addr, pkts := listenUDP(t)
	const rate = 5
	s := NewSFlow(newExporter(t, addr), rate, net.ParseIP("10.0.0.1").To4())
	pkt := rawPacket()
	for i := 0; i < rate*3; i++ {
		s.Sample(pkt)
	}
	got := 0
drain:
	for {
		select {
		case <-pkts:
			got++
		case <-time.After(150 * time.Millisecond):
			break drain
		}
	}
	if got != 3 {
		t.Errorf("rate=%d, sent %d packets → %d sFlow datagrams, want 3", rate, rate*3, got)
	}
}

// rawPacket returns a minimal Ethernet+IPv4+TCP frame as a gopacket.Packet.
func rawPacket() gopacket.Packet {
	raw := []byte{
		// Ethernet (14 bytes)
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x08, 0x00,
		// IPv4 (20 bytes): TTL=64, proto=6 (TCP)
		0x45, 0x00, 0x00, 0x28,
		0x00, 0x01, 0x00, 0x00,
		0x40, 0x06, 0x00, 0x00,
		10, 0, 2, 30, // src
		10, 0, 1, 10, // dst
		// TCP (20 bytes)
		0x1E, 0x61, 0x00, 0x50,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x50, 0x02, 0xFF, 0xFF,
		0x00, 0x00, 0x00, 0x00,
	}
	return gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)
}
