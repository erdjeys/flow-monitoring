// Package anomaly provides real-time flow-based anomaly detection.
// It maintains a per-source-IP sliding window and emits structured alerts
// when behaviour matches known attack or compromise signatures.
package anomaly

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/flowmonitor/collector/influx"
)

// ── Alert types ───────────────────────────────────────────────────────────────

// AlertType classifies a detected anomaly.
type AlertType string

const (
	// AlertPortScan fires when one source probes ≥30 distinct destination
	// ports within the sliding window — typical TCP/UDP reconnaissance.
	AlertPortScan AlertType = "PORT_SCAN"

	// AlertLateralMovement fires when one source contacts ≥8 distinct
	// internal hosts — typical post-compromise internal reconnaissance.
	AlertLateralMovement AlertType = "LATERAL_MOVEMENT"

	// AlertDataExfiltration fires when a single flow carries ≥5 MB to an
	// external (non-RFC-1918) IP — may indicate data theft.
	AlertDataExfiltration AlertType = "DATA_EXFILTRATION"

	// AlertSensorNetBreach fires the first time an external IP appears as
	// the source of traffic toward the sensor network (10.0.2.0/24).
	// Sensor nets should be internally isolated; unexpected external sources
	// suggest radio-interception or command-injection attempts.
	AlertSensorNetBreach AlertType = "SENSOR_NET_BREACH"

	// AlertRadioBeacon fires when a sensor-net device sends very regular
	// small UDP flows to the same external peer — possible RF beacon leakage
	// or unauthorised C2 channel.
	AlertRadioBeacon AlertType = "RADIO_BEACON"
)

// Severity encodes the urgency of an alert.
type Severity int

const (
	SeverityLow    Severity = 1
	SeverityMedium Severity = 2
	SeverityHigh   Severity = 3
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	default:
		return "UNKNOWN"
	}
}

// Alert is one detected anomaly event.
type Alert struct {
	Time      time.Time `json:"time"`
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	AlertType AlertType `json:"alert_type"`
	Severity  string    `json:"severity"`
	Detail    string    `json:"detail"`
}

// ── Detection thresholds ──────────────────────────────────────────────────────

const (
	portScanPortThreshold    = 30          // unique dst ports → port scan
	lateralMoveIPThreshold   = 8           // unique internal dst IPs → lateral movement
	exfilBytesThreshold      = 5 << 20     // 5 MB in one flow → exfiltration
	beaconMinFlows           = 6           // min samples to classify as beacon
	beaconMaxIntervalJitter  = 3.0         // max coefficient of variation for "regular" interval
	windowDuration           = 5 * time.Minute
	maxAlerts                = 500
	sensorNet                = "10.0.2."
)

// ── Per-IP sliding window ────────────────────────────────────────────────────

// ipWindow tracks short-term behaviour for one source IP.
type ipWindow struct {
	firstSeen      time.Time
	lastSeen       time.Time
	uniqueDstIPs   map[string]struct{}
	uniqueDstPorts map[uint16]struct{}
	totalBytes     uint64

	// For beacon detection: flow timestamps from this src to the same external peer.
	// key = dstIP, value = sorted list of arrival times.
	beaconCandidates map[string][]time.Time
}

func newIPWindow() *ipWindow {
	return &ipWindow{
		firstSeen:        time.Now(),
		lastSeen:         time.Now(),
		uniqueDstIPs:     make(map[string]struct{}),
		uniqueDstPorts:   make(map[uint16]struct{}),
		beaconCandidates: make(map[string][]time.Time),
	}
}

// ── Detector ─────────────────────────────────────────────────────────────────

// Detector analyses incoming flow records in real time and produces alerts.
// It is safe for concurrent use.
type Detector struct {
	mu      sync.Mutex
	windows map[string]*ipWindow // key = src IP string

	// knownSensorPeers tracks external IPs that have already been seen
	// communicating with the sensor network (suppresses duplicate breach alerts).
	knownSensorPeers map[string]struct{}

	alerts  []Alert      // ring buffer, capped at maxAlerts
	onAlert func(Alert)  // optional persistence hook (called outside the lock)
}

// NewDetector creates a ready-to-use Detector.
func NewDetector() *Detector {
	return &Detector{
		windows:          make(map[string]*ipWindow),
		knownSensorPeers: make(map[string]struct{}),
	}
}

// OnAlert registers a callback that fires for every new alert.
// It is called in a separate goroutine so it must not hold d.mu.
// Typical use: persist the alert to a database.
func (d *Detector) OnAlert(fn func(Alert)) {
	d.mu.Lock()
	d.onAlert = fn
	d.mu.Unlock()
}

// Alerts returns a snapshot of recent alerts (newest last).
func (d *Detector) Alerts() []Alert {
	d.mu.Lock()
	out := make([]Alert, len(d.alerts))
	copy(out, d.alerts)
	d.mu.Unlock()
	return out
}

func (d *Detector) emit(a Alert) {
	if len(d.alerts) >= maxAlerts {
		// Rotate: discard the oldest quarter.
		d.alerts = d.alerts[maxAlerts/4:]
	}
	d.alerts = append(d.alerts, a)
	if d.onAlert != nil {
		fn := d.onAlert
		go fn(a) // call outside the lock to avoid blocking the detector
	}
}

// Observe processes one incoming flow record and runs all detection rules.
func (d *Detector) Observe(r *influx.FlowRecord) {
	if r.SrcIP == "" || r.SrcIP == "0.0.0.0" || r.DstIP == "" {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()

	// Expire stale windows.
	for ip, w := range d.windows {
		if now.Sub(w.lastSeen) > windowDuration {
			delete(d.windows, ip)
		}
	}

	w, ok := d.windows[r.SrcIP]
	if !ok {
		w = newIPWindow()
		d.windows[r.SrcIP] = w
	}
	w.lastSeen = now
	w.totalBytes += r.Bytes
	w.uniqueDstIPs[r.DstIP] = struct{}{}
	if r.DstPort > 0 {
		w.uniqueDstPorts[r.DstPort] = struct{}{}
	}

	// ── Rule 1: Port scan ─────────────────────────────────────────────────────
	if len(w.uniqueDstPorts) >= portScanPortThreshold {
		d.emit(Alert{
			Time: now, SrcIP: r.SrcIP, DstIP: r.DstIP,
			AlertType: AlertPortScan, Severity: SeverityMedium.String(),
			Detail: fmt.Sprintf(
				"%s scanned %d unique destination ports across %d hosts in %s",
				r.SrcIP, len(w.uniqueDstPorts), len(w.uniqueDstIPs),
				time.Since(w.firstSeen).Round(time.Second)),
		})
		// Reset port set to avoid alert flooding but keep host tracking.
		w.uniqueDstPorts = make(map[uint16]struct{})
	}

	// ── Rule 2: Lateral movement ──────────────────────────────────────────────
	internalPeers := 0
	for dip := range w.uniqueDstIPs {
		if isPrivate(dip) {
			internalPeers++
		}
	}
	if internalPeers >= lateralMoveIPThreshold {
		d.emit(Alert{
			Time: now, SrcIP: r.SrcIP, DstIP: r.DstIP,
			AlertType: AlertLateralMovement, Severity: SeverityHigh.String(),
			Detail: fmt.Sprintf(
				"%s contacted %d distinct internal hosts in %s — possible lateral movement",
				r.SrcIP, internalPeers,
				time.Since(w.firstSeen).Round(time.Second)),
		})
		w.uniqueDstIPs = make(map[string]struct{}) // reset to avoid re-fire
	}

	// ── Rule 3: Data exfiltration ─────────────────────────────────────────────
	if r.Bytes >= exfilBytesThreshold && !isPrivate(r.DstIP) {
		d.emit(Alert{
			Time: now, SrcIP: r.SrcIP, DstIP: r.DstIP,
			AlertType: AlertDataExfiltration, Severity: SeverityHigh.String(),
			Detail: fmt.Sprintf(
				"%.1f MB sent from %s to external host %s in a single flow",
				float64(r.Bytes)/(1<<20), r.SrcIP, r.DstIP),
		})
	}

	// ── Rule 4: External source accessing the sensor network ──────────────────
	if strings.HasPrefix(r.DstIP, sensorNet) && !isPrivate(r.SrcIP) {
		if _, known := d.knownSensorPeers[r.SrcIP]; !known {
			d.knownSensorPeers[r.SrcIP] = struct{}{}
			d.emit(Alert{
				Time: now, SrcIP: r.SrcIP, DstIP: r.DstIP,
				AlertType: AlertSensorNetBreach, Severity: SeverityHigh.String(),
				Detail: fmt.Sprintf(
					"external IP %s contacted sensor-net device %s for the first time — "+
						"possible radio-interception or unauthorised command injection",
					r.SrcIP, r.DstIP),
			})
		}
	}

	// ── Rule 5: Radio beacon detection ────────────────────────────────────────
	// Small, regular UDP flows from a sensor-net IP to the same external peer
	// suggest an unauthorised beacon or RF leakage channel.
	if strings.HasPrefix(r.SrcIP, sensorNet) && !isPrivate(r.DstIP) &&
		r.IPProto == 17 && r.Bytes < 1500 {

		times := w.beaconCandidates[r.DstIP]
		times = append(times, now)
		// Keep only the most recent windowDuration worth.
		cutoff := now.Add(-windowDuration)
		for len(times) > 0 && times[0].Before(cutoff) {
			times = times[1:]
		}
		w.beaconCandidates[r.DstIP] = times

		if len(times) >= beaconMinFlows {
			cv := intervalCoeffVariation(times)
			if cv <= beaconMaxIntervalJitter {
				d.emit(Alert{
					Time: now, SrcIP: r.SrcIP, DstIP: r.DstIP,
					AlertType: AlertRadioBeacon, Severity: SeverityHigh.String(),
					Detail: fmt.Sprintf(
						"sensor %s sends regular UDP micro-flows to external %s "+
							"(%.0f s interval, CV=%.2f) — possible RF beacon or C2 channel",
						r.SrcIP, r.DstIP,
						avgInterval(times).Seconds(), cv),
				})
				// Reset to suppress repeated alerts until pattern breaks.
				w.beaconCandidates[r.DstIP] = nil
			}
		}
	}
}

// ── Statistical helpers ───────────────────────────────────────────────────────

// avgInterval computes the mean time between consecutive timestamps.
func avgInterval(ts []time.Time) time.Duration {
	if len(ts) < 2 {
		return 0
	}
	var total time.Duration
	for i := 1; i < len(ts); i++ {
		total += ts[i].Sub(ts[i-1])
	}
	return total / time.Duration(len(ts)-1)
}

// intervalCoeffVariation returns the coefficient of variation of inter-arrival
// times (stddev / mean). A value near 0 = very regular = beacon-like.
func intervalCoeffVariation(ts []time.Time) float64 {
	if len(ts) < 3 {
		return 99.0 // insufficient data → not a beacon
	}
	intervals := make([]float64, len(ts)-1)
	var sum float64
	for i := 1; i < len(ts); i++ {
		d := float64(ts[i].Sub(ts[i-1]).Milliseconds())
		intervals[i-1] = d
		sum += d
	}
	mean := sum / float64(len(intervals))
	if mean == 0 {
		return 0
	}
	var variance float64
	for _, v := range intervals {
		diff := v - mean
		variance += diff * diff
	}
	variance /= float64(len(intervals))
	stddev := 0.0
	if variance > 0 {
		// Integer square root approximation sufficient here.
		stddev = variance
		for i := 0; i < 30; i++ {
			stddev = (stddev + variance/stddev) / 2
		}
	}
	return stddev / mean
}

// isPrivate reports whether ipStr falls within an RFC-1918 private range.
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
