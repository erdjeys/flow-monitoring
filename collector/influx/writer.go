package influx

import (
	"context"
	"log"
	"net"
	"time"

	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/influxdata/influxdb-client-go/v2/api"
)

// FlowRecord is a normalised flow entry produced by all three parsers.
type FlowRecord struct {
	Protocol         string
	SrcIP            string
	DstIP            string
	SrcMAC           string
	DstMAC           string
	SrcPort          uint16
	DstPort          uint16
	IPProto          uint8
	ToS              uint8
	TCPFlags         uint8
	Packets          uint64
	Bytes            uint64
	Start            time.Time
	End              time.Time
	SignalStrength   int8
	EncryptionStatus uint8
	SensorStatus     uint8 // 0=OK 1=WARNING 2=ERROR (enterprise IE 3)
	CpuLoad          uint8 // agent CPU utilisation 0-100 % (enterprise IE 4)
}

// Writer buffers and writes FlowRecords to InfluxDB.
type Writer struct {
	client   influxdb2.Client
	writeAPI api.WriteAPIBlocking
}

func NewWriter(url, token, org, bucket string) *Writer {
	client := influxdb2.NewClient(url, token)
	return &Writer{client: client, writeAPI: client.WriteAPIBlocking(org, bucket)}
}

func (w *Writer) WriteFlow(r *FlowRecord) {
	service := serviceLabel(r.DstPort)
	if service == "other" {
		service = serviceLabel(r.SrcPort)
	}
	srcPrivate := isPrivate(r.SrcIP)
	dstPrivate := isPrivate(r.DstIP)
	duration := r.End.Sub(r.Start).Milliseconds()
	if duration < 0 {
		duration = 0
	}

	p := influxdb2.NewPoint(
		"flow",
		map[string]string{
			"protocol":  r.Protocol,
			"src_ip":    r.SrcIP,
			"dst_ip":    r.DstIP,
			"ip_proto":  protoName(r.IPProto),
			"service":   service,
			"direction": flowDirection(srcPrivate, dstPrivate),
		},
		map[string]interface{}{
			"src_port":          int(r.SrcPort),
			"dst_port":          int(r.DstPort),
			"packets":           int64(r.Packets),
			"bytes":             int64(r.Bytes),
			"tcp_flags":         int(r.TCPFlags),
			"tos":               int(r.ToS),
			"duration_ms":       duration,
			"signal_strength":   int(r.SignalStrength),
			"encryption_status": int(r.EncryptionStatus),
			"sensor_status":     int(r.SensorStatus),
			"cpu_load":          int(r.CpuLoad),
			"src_mac":           r.SrcMAC,
			"dst_mac":           r.DstMAC,
		},
		r.End,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.writeAPI.WritePoint(ctx, p); err != nil {
		log.Printf("influx write: %v", err)
	}
}

func (w *Writer) Close() { w.client.Close() }

func serviceLabel(port uint16) string {
	switch port {
	case 80:
		return "http"
	case 443:
		return "https"
	case 53:
		return "dns"
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	default:
		return "other"
	}
}

func isPrivate(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		_, n, _ := net.ParseCIDR(cidr)
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func flowDirection(srcPriv, dstPriv bool) string {
	switch {
	case srcPriv && dstPriv:
		return "internal"
	case srcPriv:
		return "outbound"
	case dstPriv:
		return "inbound"
	default:
		return "external"
	}
}

func protoName(proto uint8) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	default:
		return "other"
	}
}
