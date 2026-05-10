// Package responder implements automatic incident response:
// when the anomaly detector fires an alert, the responder reacts by calling
// the monitoring agent's control-plane API to adjust its behaviour in real time.
//
// Response matrix
// ───────────────────────────────────────────────────────────────────────────
//  PORT_SCAN          → switch agent to protocol-level aggregation (reduces
//                       noise; still preserves per-src/dst-proto visibility)
//
//  LATERAL_MOVEMENT   → switch to host-pair aggregation at max 50 records
//                       (narrow-channel mode: keeps only the busiest pairs)
//
//  DATA_EXFILTRATION  → aggressive host-pair aggregation at max 20 records
//                       (shedding bulk records focuses capacity on the event)
//
//  SENSOR_NET_BREACH  → switch IPFIX template to full forensic mode
//                       (captures MAC, signal, encryption, sensor status, CPU)
//
//  RADIO_BEACON       → log only (beacon is an RF channel — the network-layer
//                       response is forensic logging, not traffic shaping)
// ───────────────────────────────────────────────────────────────────────────
package responder

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/flowmonitor/collector/anomaly"
)

// Responder calls the agent's HTTP API in reaction to anomaly alerts.
type Responder struct {
	agentAPI string
	client   *http.Client
}

// New creates a Responder that targets the agent at agentAPI (e.g. "http://10.0.3.20:8080").
func New(agentAPI string) *Responder {
	return &Responder{
		agentAPI: agentAPI,
		client:   &http.Client{Timeout: 5 * time.Second},
	}
}

// OnAlert is the callback to register with anomaly.Detector.OnAlert.
// It is always called in a goroutine (non-blocking for the detector).
func (r *Responder) OnAlert(a anomaly.Alert) {
	switch a.AlertType {

	case anomaly.AlertPortScan:
		log.Printf("[RESPONSE] PORT_SCAN from %s → protocol-level aggregation", a.SrcIP)
		r.postJSON(r.agentAPI+"/api/aggregate", map[string]interface{}{
			"enabled":     true,
			"level":       "protocol",
			"max_records": 100,
		})

	case anomaly.AlertLateralMovement:
		log.Printf("[RESPONSE] LATERAL_MOVEMENT from %s → host-pair aggregation (narrow channel)", a.SrcIP)
		r.postJSON(r.agentAPI+"/api/aggregate", map[string]interface{}{
			"enabled":     true,
			"level":       "host_pair",
			"max_records": 50,
		})

	case anomaly.AlertDataExfiltration:
		log.Printf("[RESPONSE] DATA_EXFILTRATION %s→%s → aggressive aggregation", a.SrcIP, a.DstIP)
		r.postJSON(r.agentAPI+"/api/aggregate", map[string]interface{}{
			"enabled":     true,
			"level":       "host_pair",
			"max_records": 20,
		})

	case anomaly.AlertSensorNetBreach:
		log.Printf("[RESPONSE] SENSOR_NET_BREACH %s→%s → switching IPFIX to full forensic template", a.SrcIP, a.DstIP)
		r.postJSON(r.agentAPI+"/api/ipfix/template", map[string]interface{}{
			"fields": []string{
				"srcIP", "dstIP", "srcPort", "dstPort",
				"proto", "tos", "tcpFlags",
				"packets", "bytes", "flowStart", "flowEnd",
				"srcMAC", "dstMAC",
				"signalStrength", "encryptionStatus", "sensorStatus", "cpuLoad",
			},
		})

	case anomaly.AlertRadioBeacon:
		// RF beacon: network-layer aggregation changes won't stop the beacon.
		// Log for forensic analysis; a human operator should investigate.
		log.Printf("[RESPONSE] RADIO_BEACON from sensor %s to external %s — "+
			"logged for forensic review; manual investigation required", a.SrcIP, a.DstIP)
	}
}

// postJSON marshals body to JSON and POSTs it to url, logging any errors.
func (r *Responder) postJSON(url string, body interface{}) {
	data, err := json.Marshal(body)
	if err != nil {
		log.Printf("[RESPONSE] marshal error: %v", err)
		return
	}
	resp, err := r.client.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		log.Printf("[RESPONSE] POST %s failed: %v", url, err)
		return
	}
	defer resp.Body.Close()
	log.Printf("[RESPONSE] POST %s → HTTP %d", url, resp.StatusCode)
}
