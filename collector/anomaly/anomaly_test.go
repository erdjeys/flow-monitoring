// Unit tests for the anomaly detector.
//
// White-box (package anomaly) so we can access unexported helpers, thresholds,
// and the windows map directly for window-expiry and ring-buffer tests.
//
// Run with: go test ./anomaly/... -v -race
package anomaly

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/flowmonitor/collector/influx"
)

// ── Test helpers ──────────────────────────────────────────────────────────────

func mkFlow(srcIP, dstIP string, dstPort uint16, proto uint8, bytes uint64) *influx.FlowRecord {
	return &influx.FlowRecord{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		DstPort: dstPort,
		IPProto: proto,
		Bytes:   bytes,
	}
}

func hasAlert(alerts []Alert, typ AlertType) bool {
	for _, a := range alerts {
		if a.AlertType == typ {
			return true
		}
	}
	return false
}

func alertCount(alerts []Alert, typ AlertType) int {
	n := 0
	for _, a := range alerts {
		if a.AlertType == typ {
			n++
		}
	}
	return n
}

// ── isPrivate ─────────────────────────────────────────────────────────────────

func TestIsPrivate_RFC1918_Private(t *testing.T) {
	cases := []string{
		"10.0.0.1", "10.255.255.255",
		"172.16.0.1", "172.31.255.255",
		"192.168.0.1", "192.168.255.255",
	}
	for _, ip := range cases {
		if !isPrivate(ip) {
			t.Errorf("isPrivate(%q) = false, want true", ip)
		}
	}
}

func TestIsPrivate_Public_IPs(t *testing.T) {
	cases := []string{
		"8.8.8.8", "1.1.1.1",
		"172.32.0.1", // just outside 172.16/12
		"172.15.255.255",
	}
	for _, ip := range cases {
		if isPrivate(ip) {
			t.Errorf("isPrivate(%q) = true, want false", ip)
		}
	}
}

func TestIsPrivate_InvalidInputs(t *testing.T) {
	cases := []string{"", "invalid", "256.0.0.1", "not-an-ip"}
	for _, ip := range cases {
		if isPrivate(ip) {
			t.Errorf("isPrivate(%q) = true, want false for invalid input", ip)
		}
	}
}

// ── avgInterval ───────────────────────────────────────────────────────────────

func TestAvgInterval_Empty(t *testing.T) {
	if got := avgInterval(nil); got != 0 {
		t.Errorf("avgInterval(nil) = %v, want 0", got)
	}
}

func TestAvgInterval_Single(t *testing.T) {
	if got := avgInterval([]time.Time{time.Now()}); got != 0 {
		t.Errorf("avgInterval([1 ts]) = %v, want 0", got)
	}
}

func TestAvgInterval_Regular(t *testing.T) {
	base := time.Now()
	ts := []time.Time{base, base.Add(time.Second), base.Add(2 * time.Second)}
	got := avgInterval(ts)
	if got != time.Second {
		t.Errorf("avgInterval = %v, want 1s", got)
	}
}

// ── intervalCoeffVariation ───────────────────────────────────────────────────

func TestIntervalCoeffVariation_TooFewSamples(t *testing.T) {
	base := time.Now()
	cases := [][]time.Time{
		nil,
		{base},
		{base, base.Add(time.Second)},
	}
	for _, ts := range cases {
		if v := intervalCoeffVariation(ts); v != 99.0 {
			t.Errorf("intervalCoeffVariation(%d samples) = %f, want 99.0", len(ts), v)
		}
	}
}

func TestIntervalCoeffVariation_Regular(t *testing.T) {
	// 7 timestamps, each exactly 1 second apart → CV ≈ 0 (perfectly regular beacon)
	base := time.Now()
	ts := make([]time.Time, 7)
	for i := 0; i < 7; i++ {
		ts[i] = base.Add(time.Duration(i) * time.Second)
	}
	cv := intervalCoeffVariation(ts)
	if cv > 0.01 {
		t.Errorf("perfectly regular intervals → CV = %.4f, want ≈ 0", cv)
	}
}

func TestIntervalCoeffVariation_Irregular(t *testing.T) {
	// 12 timestamps: 10 rapid (1 ms each) + 1 large gap (10 s)
	// Produces 11 intervals: [1,1,1,1,1,1,1,1,1,1,10000] ms
	// CV = sqrt(10) ≈ 3.16, which exceeds beaconMaxIntervalJitter (3.0).
	base := time.Now()
	ts := make([]time.Time, 12)
	for i := 0; i < 11; i++ {
		ts[i] = base.Add(time.Duration(i) * time.Millisecond)
	}
	ts[11] = base.Add(10*time.Second + 10*time.Millisecond)

	cv := intervalCoeffVariation(ts)
	if cv <= beaconMaxIntervalJitter {
		t.Errorf("irregular intervals → CV = %.2f, expected > %.1f", cv, float64(beaconMaxIntervalJitter))
	}
}

// ── Port scan ─────────────────────────────────────────────────────────────────

func TestDetector_PortScan_FiresAtThreshold(t *testing.T) {
	d := NewDetector()
	// Send portScanPortThreshold flows from the same source, each to a distinct port.
	for i := 0; i < portScanPortThreshold; i++ {
		d.Observe(mkFlow("10.0.0.1", "10.0.1.10", uint16(1000+i), 6, 100))
	}
	if !hasAlert(d.Alerts(), AlertPortScan) {
		t.Error("expected AlertPortScan after hitting port threshold, got none")
	}
}

func TestDetector_PortScan_BelowThreshold_NoAlert(t *testing.T) {
	d := NewDetector()
	for i := 0; i < portScanPortThreshold-1; i++ {
		d.Observe(mkFlow("10.0.0.1", "10.0.1.10", uint16(1000+i), 6, 100))
	}
	if hasAlert(d.Alerts(), AlertPortScan) {
		t.Error("AlertPortScan fired before reaching port threshold")
	}
}

func TestDetector_PortScan_ResetsAfterAlert(t *testing.T) {
	d := NewDetector()
	// Trigger the first alert.
	for i := 0; i < portScanPortThreshold; i++ {
		d.Observe(mkFlow("10.0.0.1", "10.0.1.10", uint16(1000+i), 6, 100))
	}
	firstCount := alertCount(d.Alerts(), AlertPortScan)

	// Send threshold-1 more distinct ports — must NOT fire again.
	for i := 0; i < portScanPortThreshold-1; i++ {
		d.Observe(mkFlow("10.0.0.1", "10.0.1.10", uint16(5000+i), 6, 100))
	}
	if alertCount(d.Alerts(), AlertPortScan) != firstCount {
		t.Error("AlertPortScan fired again before port set refilled to threshold")
	}
}

func TestDetector_PortScan_AlertContainsSrcIP(t *testing.T) {
	d := NewDetector()
	for i := 0; i < portScanPortThreshold; i++ {
		d.Observe(mkFlow("192.168.5.99", "10.0.1.10", uint16(1000+i), 6, 100))
	}
	for _, a := range d.Alerts() {
		if a.AlertType == AlertPortScan {
			if a.SrcIP != "192.168.5.99" {
				t.Errorf("alert SrcIP = %q, want 192.168.5.99", a.SrcIP)
			}
			if a.Severity != SeverityMedium.String() {
				t.Errorf("alert Severity = %q, want MEDIUM", a.Severity)
			}
			return
		}
	}
	t.Error("no AlertPortScan found")
}

// ── Lateral movement ──────────────────────────────────────────────────────────

func TestDetector_LateralMovement_FiresAtThreshold(t *testing.T) {
	d := NewDetector()
	for i := 0; i < lateralMoveIPThreshold; i++ {
		d.Observe(mkFlow("10.0.0.5", fmt.Sprintf("10.0.1.%d", i+1), 80, 6, 100))
	}
	if !hasAlert(d.Alerts(), AlertLateralMovement) {
		t.Error("expected AlertLateralMovement, got none")
	}
}

func TestDetector_LateralMovement_BelowThreshold_NoAlert(t *testing.T) {
	d := NewDetector()
	for i := 0; i < lateralMoveIPThreshold-1; i++ {
		d.Observe(mkFlow("10.0.0.5", fmt.Sprintf("10.0.1.%d", i+1), 80, 6, 100))
	}
	if hasAlert(d.Alerts(), AlertLateralMovement) {
		t.Error("AlertLateralMovement fired before reaching IP threshold")
	}
}

func TestDetector_LateralMovement_ResetsAfterAlert(t *testing.T) {
	d := NewDetector()
	// Trigger first alert.
	for i := 0; i < lateralMoveIPThreshold; i++ {
		d.Observe(mkFlow("10.0.0.5", fmt.Sprintf("10.0.1.%d", i+1), 80, 6, 100))
	}
	count1 := alertCount(d.Alerts(), AlertLateralMovement)

	// Send threshold-1 more unique internal IPs — must NOT re-fire.
	for i := 0; i < lateralMoveIPThreshold-1; i++ {
		d.Observe(mkFlow("10.0.0.5", fmt.Sprintf("10.0.2.%d", i+1), 80, 6, 100))
	}
	if alertCount(d.Alerts(), AlertLateralMovement) != count1 {
		t.Error("AlertLateralMovement re-fired before IP set refilled to threshold")
	}
}

func TestDetector_LateralMovement_ExternalDstNotCounted(t *testing.T) {
	// Traffic to external (non-private) IPs must not count toward lateral movement.
	d := NewDetector()
	for i := 0; i < lateralMoveIPThreshold; i++ {
		// All destinations are public — not internal peers.
		d.Observe(mkFlow("10.0.0.5", fmt.Sprintf("8.8.%d.1", i), 80, 6, 100))
	}
	if hasAlert(d.Alerts(), AlertLateralMovement) {
		t.Error("AlertLateralMovement fired for external destinations")
	}
}

// ── Data exfiltration ─────────────────────────────────────────────────────────

func TestDetector_DataExfiltration_FiresOnLargeExternalFlow(t *testing.T) {
	d := NewDetector()
	d.Observe(mkFlow("10.0.0.1", "8.8.8.8", 443, 6, exfilBytesThreshold+1))
	if !hasAlert(d.Alerts(), AlertDataExfiltration) {
		t.Error("expected AlertDataExfiltration for ≥5 MB external flow, got none")
	}
}

func TestDetector_DataExfiltration_NoAlertForPrivateDst(t *testing.T) {
	d := NewDetector()
	// Large flow to internal IP → no exfiltration alert.
	d.Observe(mkFlow("10.0.0.1", "10.0.1.10", 443, 6, exfilBytesThreshold+1))
	if hasAlert(d.Alerts(), AlertDataExfiltration) {
		t.Error("AlertDataExfiltration fired for private destination")
	}
}

func TestDetector_DataExfiltration_NoAlertBelowThreshold(t *testing.T) {
	d := NewDetector()
	d.Observe(mkFlow("10.0.0.1", "8.8.8.8", 443, 6, exfilBytesThreshold-1))
	if hasAlert(d.Alerts(), AlertDataExfiltration) {
		t.Error("AlertDataExfiltration fired below 5 MB threshold")
	}
}

// ── Sensor network breach ─────────────────────────────────────────────────────

func TestDetector_SensorNetBreach_FiresOnFirstContact(t *testing.T) {
	d := NewDetector()
	// External source → sensor-net device.
	d.Observe(mkFlow("8.8.8.8", "10.0.2.30", 22, 6, 200))
	if !hasAlert(d.Alerts(), AlertSensorNetBreach) {
		t.Error("expected AlertSensorNetBreach for external→sensor-net traffic, got none")
	}
}

func TestDetector_SensorNetBreach_SuppressDuplicate(t *testing.T) {
	d := NewDetector()
	// First flow from external → alert.
	d.Observe(mkFlow("8.8.8.8", "10.0.2.30", 22, 6, 200))
	// Second flow from same external → must not fire again.
	d.Observe(mkFlow("8.8.8.8", "10.0.2.31", 22, 6, 200))
	if alertCount(d.Alerts(), AlertSensorNetBreach) != 1 {
		t.Errorf("expected exactly 1 AlertSensorNetBreach, got %d", alertCount(d.Alerts(), AlertSensorNetBreach))
	}
}

func TestDetector_SensorNetBreach_NewExternalIPFiresAgain(t *testing.T) {
	d := NewDetector()
	d.Observe(mkFlow("8.8.8.8", "10.0.2.30", 22, 6, 200))
	d.Observe(mkFlow("1.2.3.4", "10.0.2.30", 22, 6, 200)) // different external IP
	if alertCount(d.Alerts(), AlertSensorNetBreach) != 2 {
		t.Errorf("expected 2 AlertSensorNetBreach (one per external IP), got %d",
			alertCount(d.Alerts(), AlertSensorNetBreach))
	}
}

func TestDetector_SensorNetBreach_NoAlertForPrivateSrc(t *testing.T) {
	d := NewDetector()
	// Internal source → sensor-net device: normal traffic, no breach.
	d.Observe(mkFlow("10.0.1.10", "10.0.2.30", 22, 6, 200))
	if hasAlert(d.Alerts(), AlertSensorNetBreach) {
		t.Error("AlertSensorNetBreach fired for private source IP")
	}
}

// ── Radio beacon ──────────────────────────────────────────────────────────────

func TestDetector_RadioBeacon_FiresOnRegularMicroFlows(t *testing.T) {
	d := NewDetector()
	// Six rapid UDP micro-flows from sensor-net to external.
	// All within the same millisecond → all inter-arrival intervals ≈ 0 ms.
	// intervalCoeffVariation returns 0 when mean == 0 → fires the beacon.
	for i := 0; i < beaconMinFlows; i++ {
		d.Observe(mkFlow("10.0.2.30", "8.8.8.8", 53, 17, 64))
	}
	if !hasAlert(d.Alerts(), AlertRadioBeacon) {
		t.Error("expected AlertRadioBeacon for regular micro-flows from sensor-net, got none")
	}
}

func TestDetector_RadioBeacon_NoAlertBelowMinFlows(t *testing.T) {
	d := NewDetector()
	for i := 0; i < beaconMinFlows-1; i++ {
		d.Observe(mkFlow("10.0.2.30", "8.8.8.8", 53, 17, 64))
	}
	if hasAlert(d.Alerts(), AlertRadioBeacon) {
		t.Error("AlertRadioBeacon fired with fewer than beaconMinFlows samples")
	}
}

func TestDetector_RadioBeacon_NoAlertForLargeFlows(t *testing.T) {
	// Large UDP flows (≥1500 bytes) must NOT contribute to beacon detection.
	d := NewDetector()
	for i := 0; i < beaconMinFlows+5; i++ {
		d.Observe(mkFlow("10.0.2.30", "8.8.8.8", 53, 17, 1500))
	}
	if hasAlert(d.Alerts(), AlertRadioBeacon) {
		t.Error("AlertRadioBeacon fired for large (≥1500 B) UDP flows")
	}
}

func TestDetector_RadioBeacon_NoAlertForInternalDst(t *testing.T) {
	// Micro-flows to an internal IP must NOT trigger beacon (not exfiltration path).
	d := NewDetector()
	for i := 0; i < beaconMinFlows+5; i++ {
		d.Observe(mkFlow("10.0.2.30", "10.0.1.10", 53, 17, 64))
	}
	if hasAlert(d.Alerts(), AlertRadioBeacon) {
		t.Error("AlertRadioBeacon fired for internal destination")
	}
}

func TestDetector_RadioBeacon_NoAlertForNonSensorSrc(t *testing.T) {
	// Micro-flows from a non-sensor-net IP must NOT trigger beacon.
	d := NewDetector()
	for i := 0; i < beaconMinFlows+5; i++ {
		d.Observe(mkFlow("10.0.1.10", "8.8.8.8", 53, 17, 64))
	}
	if hasAlert(d.Alerts(), AlertRadioBeacon) {
		t.Error("AlertRadioBeacon fired for non-sensor-net source")
	}
}

func TestDetector_RadioBeacon_ResetsAfterAlert(t *testing.T) {
	d := NewDetector()
	// Trigger beacon.
	for i := 0; i < beaconMinFlows; i++ {
		d.Observe(mkFlow("10.0.2.30", "8.8.8.8", 53, 17, 64))
	}
	count1 := alertCount(d.Alerts(), AlertRadioBeacon)

	// Fewer than beaconMinFlows new flows → no re-fire.
	for i := 0; i < beaconMinFlows-1; i++ {
		d.Observe(mkFlow("10.0.2.30", "8.8.8.8", 53, 17, 64))
	}
	if alertCount(d.Alerts(), AlertRadioBeacon) != count1 {
		t.Error("AlertRadioBeacon re-fired before candidate list refilled")
	}
}

// ── Invalid / edge-case inputs ────────────────────────────────────────────────

func TestDetector_Observe_EmptySrcIP_Ignored(t *testing.T) {
	d := NewDetector()
	d.Observe(&influx.FlowRecord{SrcIP: "", DstIP: "10.0.1.10", IPProto: 6, Bytes: 100})
	if len(d.Alerts()) != 0 {
		t.Error("flow with empty SrcIP should be silently dropped")
	}
}

func TestDetector_Observe_ZeroSrcIP_Ignored(t *testing.T) {
	d := NewDetector()
	d.Observe(&influx.FlowRecord{SrcIP: "0.0.0.0", DstIP: "10.0.1.10", IPProto: 6, Bytes: 100})
	if len(d.Alerts()) != 0 {
		t.Error("flow with 0.0.0.0 SrcIP should be silently dropped")
	}
}

func TestDetector_Observe_EmptyDstIP_Ignored(t *testing.T) {
	d := NewDetector()
	d.Observe(&influx.FlowRecord{SrcIP: "10.0.0.1", DstIP: "", IPProto: 6, Bytes: 100})
	if len(d.Alerts()) != 0 {
		t.Error("flow with empty DstIP should be silently dropped")
	}
}

// ── OnAlert callback ──────────────────────────────────────────────────────────

func TestDetector_OnAlert_CalledInGoroutine(t *testing.T) {
	d := NewDetector()

	var mu sync.Mutex
	var received []Alert
	fired := make(chan struct{}, 1)

	d.OnAlert(func(a Alert) {
		mu.Lock()
		received = append(received, a)
		mu.Unlock()
		select {
		case fired <- struct{}{}:
		default:
		}
	})

	// Trigger a port scan alert.
	for i := 0; i < portScanPortThreshold; i++ {
		d.Observe(mkFlow("10.0.0.1", "10.0.1.10", uint16(1000+i), 6, 100))
	}

	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("OnAlert callback not called within 2 s")
	}

	mu.Lock()
	n := len(received)
	mu.Unlock()
	if n < 1 {
		t.Errorf("expected ≥1 alert in callback, got %d", n)
	}
}

// ── Alerts snapshot ───────────────────────────────────────────────────────────

func TestDetector_Alerts_ReturnsIndependentCopy(t *testing.T) {
	d := NewDetector()

	// Trigger an alert.
	for i := 0; i < portScanPortThreshold; i++ {
		d.Observe(mkFlow("10.0.0.1", "10.0.1.10", uint16(1000+i), 6, 100))
	}

	snap := d.Alerts()
	if len(snap) == 0 {
		t.Fatal("expected at least 1 alert in snapshot")
	}

	// Mutate the snapshot.
	snap[0].SrcIP = "tampered"

	// Detector's internal slice must be unaffected.
	snap2 := d.Alerts()
	if snap2[0].SrcIP == "tampered" {
		t.Error("Alerts() returned a live slice instead of an independent copy")
	}
}

func TestDetector_Alerts_InitiallyEmpty(t *testing.T) {
	d := NewDetector()
	if got := d.Alerts(); len(got) != 0 {
		t.Errorf("fresh detector: Alerts() = %d, want 0", len(got))
	}
}

// ── Window expiry ─────────────────────────────────────────────────────────────

func TestDetector_WindowExpiry_StaleWindowEvicted(t *testing.T) {
	d := NewDetector()

	// Create a window for "10.0.0.1".
	d.Observe(mkFlow("10.0.0.1", "10.0.1.1", 80, 6, 100))

	// Age the window past windowDuration.
	d.mu.Lock()
	if w, ok := d.windows["10.0.0.1"]; ok {
		w.lastSeen = time.Now().Add(-windowDuration - time.Second)
	}
	d.mu.Unlock()

	// A new observation from another source triggers the cleanup loop.
	d.Observe(mkFlow("10.0.0.2", "10.0.1.1", 80, 6, 100))

	d.mu.Lock()
	_, stillPresent := d.windows["10.0.0.1"]
	d.mu.Unlock()

	if stillPresent {
		t.Error("stale window (lastSeen > windowDuration ago) should have been evicted")
	}
}

// ── Alert ring buffer ─────────────────────────────────────────────────────────

func TestDetector_AlertRingBuffer_NeverExceedsMaxAlerts(t *testing.T) {
	d := NewDetector()

	// Each unique src/dst pair with ≥ exfilBytesThreshold bytes triggers one
	// DATA_EXFILTRATION alert, regardless of previous windows.
	// Fire maxAlerts + 50 alerts to exercise the ring-buffer rotation.
	total := maxAlerts + 50
	for i := 0; i < total; i++ {
		srcIP := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		d.Observe(mkFlow(srcIP, "1.2.3.4", 443, 6, exfilBytesThreshold+1))
	}

	if got := len(d.Alerts()); got > maxAlerts {
		t.Errorf("ring buffer overflow: got %d alerts, limit is %d", got, maxAlerts)
	}
}
