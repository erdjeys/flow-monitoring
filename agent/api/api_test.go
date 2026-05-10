// Unit tests for the agent HTTP control-plane API.
//
// White-box (package api) so we can call srv.mux.ServeHTTP directly without
// needing a real network listener — fast and deterministic.
//
// Run with: go test ./api/... -v -race
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/flowmonitor/agent/aggregate"
	"github.com/flowmonitor/agent/flow"
)

// ── Mock implementations ──────────────────────────────────────────────────────

// mockTemplate satisfies the TemplateManager interface.
type mockTemplate struct {
	current   []string
	available []string
	setErr    error
}

func (m *mockTemplate) SetTemplate(fields []string) error {
	if m.setErr != nil {
		return m.setErr
	}
	m.current = fields
	return nil
}
func (m *mockTemplate) CurrentTemplate() []string { return m.current }
func (m *mockTemplate) AvailableFields() []string { return m.available }

// mockAgg satisfies the AggregationManager interface.
type mockAgg struct {
	cfg aggregate.Config
	st  aggregate.Stats
}

func (m *mockAgg) GetConfig() aggregate.Config   { return m.cfg }
func (m *mockAgg) SetConfig(c aggregate.Config)  { m.cfg = c }
func (m *mockAgg) Stats() aggregate.Stats        { return m.st }

// ── Test helpers ──────────────────────────────────────────────────────────────

// newTestServer returns a Server wired to convenient mock dependencies.
func newTestServer(t *testing.T) (*Server, *mockTemplate, *mockAgg) {
	t.Helper()
	tr := flow.NewTracker(time.Minute, 30*time.Second, 1000)
	tr.OnExport(func([]*flow.Record) {})

	tmpl := &mockTemplate{
		current:   []string{"srcIP", "dstIP"},
		available: []string{"srcIP", "dstIP", "srcPort", "dstPort", "proto"},
	}
	agg := &mockAgg{
		cfg: aggregate.Config{
			Enabled:    true,
			Level:      aggregate.LevelProtocol,
			MaxRecords: 100,
		},
	}
	return NewServer(tr, tmpl, agg), tmpl, agg
}

// do fires an HTTP request at the server's mux and returns the recorder.
func do(srv *Server, method, path, body string) *httptest.ResponseRecorder {
	var b *bytes.Reader
	if body != "" {
		b = bytes.NewReader([]byte(body))
	} else {
		b = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, b)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	return w
}

// ── GET /api/status ───────────────────────────────────────────────────────────

func TestAPI_Status_OK(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := do(srv, http.MethodGet, "/api/status", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/status: status %d, want 200", w.Code)
	}
	var resp statusResp
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal status response: %v\nbody: %s", err, w.Body)
	}
	if len(resp.IPFIXTemplate) != 2 {
		t.Errorf("IPFIXTemplate = %v, want [srcIP dstIP]", resp.IPFIXTemplate)
	}
}

func TestAPI_Status_ContentTypeJSON(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := do(srv, http.MethodGet, "/api/status", "")
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

// ── POST /api/problem ─────────────────────────────────────────────────────────

func TestAPI_Problem_Post_NoContent(t *testing.T) {
	srv, _, _ := newTestServer(t)
	body := `{"src_ip":"10.0.0.1","dst_ip":"10.0.1.10","protocol":6,"packet_loss":0.25,"latency_ms":100}`
	w := do(srv, http.MethodPost, "/api/problem", body)
	if w.Code != http.StatusNoContent {
		t.Errorf("POST /api/problem: status %d, want 204", w.Code)
	}
}

func TestAPI_Problem_Post_BadJSON(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := do(srv, http.MethodPost, "/api/problem", `{bad json`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("POST /api/problem bad JSON: status %d, want 400", w.Code)
	}
}

// ── DELETE /api/problem ───────────────────────────────────────────────────────

func TestAPI_Problem_Delete_NoContent(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := do(srv, http.MethodDelete, "/api/problem", "")
	if w.Code != http.StatusNoContent {
		t.Errorf("DELETE /api/problem: status %d, want 204", w.Code)
	}
}

// ── Method enforcement /api/problem ──────────────────────────────────────────

func TestAPI_Problem_MethodNotAllowed(t *testing.T) {
	srv, _, _ := newTestServer(t)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPatch} {
		w := do(srv, method, "/api/problem", "")
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /api/problem: status %d, want 405", method, w.Code)
		}
	}
}

// ── GET /api/ipfix/template ───────────────────────────────────────────────────

func TestAPI_IPFIXTemplate_Get_ReturnsActiveAndAvailable(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := do(srv, http.MethodGet, "/api/ipfix/template", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/ipfix/template: status %d, want 200", w.Code)
	}
	var resp templateResp
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Active) != 2 {
		t.Errorf("Active = %v, want 2 fields (srcIP, dstIP)", resp.Active)
	}
	if len(resp.Available) != 5 {
		t.Errorf("Available = %v, want 5 fields", resp.Available)
	}
}

// ── POST /api/ipfix/template ──────────────────────────────────────────────────

func TestAPI_IPFIXTemplate_Post_UpdatesTemplate(t *testing.T) {
	srv, tmpl, _ := newTestServer(t)
	w := do(srv, http.MethodPost, "/api/ipfix/template", `{"fields":["srcIP","dstIP","proto"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/ipfix/template: status %d, want 200\nbody: %s", w.Code, w.Body)
	}
	if len(tmpl.current) != 3 {
		t.Errorf("template not updated: got %v, want 3 fields", tmpl.current)
	}
	if tmpl.current[2] != "proto" {
		t.Errorf("third field = %q, want proto", tmpl.current[2])
	}
}

func TestAPI_IPFIXTemplate_Post_BadJSON(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := do(srv, http.MethodPost, "/api/ipfix/template", `not-json`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("POST /api/ipfix/template bad JSON: status %d, want 400", w.Code)
	}
}

func TestAPI_IPFIXTemplate_Post_SetTemplateError(t *testing.T) {
	srv, tmpl, _ := newTestServer(t)
	tmpl.setErr = errors.New("unknown field: bogus")
	w := do(srv, http.MethodPost, "/api/ipfix/template", `{"fields":["bogus"]}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("POST /api/ipfix/template with SetTemplate error: status %d, want 400", w.Code)
	}
}

func TestAPI_IPFIXTemplate_Post_ResponseContainsActive(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := do(srv, http.MethodPost, "/api/ipfix/template", `{"fields":["srcIP"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", w.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := resp["active"]; !ok {
		t.Error("POST response must include 'active' key")
	}
}

// ── Method enforcement /api/ipfix/template ────────────────────────────────────

func TestAPI_IPFIXTemplate_MethodNotAllowed(t *testing.T) {
	srv, _, _ := newTestServer(t)
	for _, method := range []string{http.MethodDelete, http.MethodPut} {
		w := do(srv, method, "/api/ipfix/template", "")
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /api/ipfix/template: status %d, want 405", method, w.Code)
		}
	}
}

// ── GET /api/aggregate ────────────────────────────────────────────────────────

func TestAPI_Aggregate_Get_ReturnsConfigAndStats(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := do(srv, http.MethodGet, "/api/aggregate", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/aggregate: status %d, want 200", w.Code)
	}
	var resp aggregateResp
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !resp.Config.Enabled {
		t.Error("expected Config.Enabled = true in default mock")
	}
	if resp.Config.Level != aggregate.LevelProtocol {
		t.Errorf("Config.Level = %q, want %q", resp.Config.Level, aggregate.LevelProtocol)
	}
}

// ── POST /api/aggregate ───────────────────────────────────────────────────────

func TestAPI_Aggregate_Post_LevelNone(t *testing.T) {
	srv, _, agg := newTestServer(t)
	w := do(srv, http.MethodPost, "/api/aggregate",
		`{"enabled":false,"level":"none","max_records":0}`)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/aggregate: status %d, want 200\nbody: %s", w.Code, w.Body)
	}
	if agg.cfg.Enabled {
		t.Error("expected Enabled = false after POST")
	}
	if agg.cfg.Level != aggregate.LevelNone {
		t.Errorf("Level = %q, want none", agg.cfg.Level)
	}
}

func TestAPI_Aggregate_Post_LevelHostPair(t *testing.T) {
	srv, _, agg := newTestServer(t)
	w := do(srv, http.MethodPost, "/api/aggregate",
		`{"enabled":true,"level":"host_pair","max_records":50}`)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/aggregate: status %d, want 200", w.Code)
	}
	if agg.cfg.Level != aggregate.LevelHostPair {
		t.Errorf("Level = %q, want host_pair", agg.cfg.Level)
	}
	if agg.cfg.MaxRecords != 50 {
		t.Errorf("MaxRecords = %d, want 50", agg.cfg.MaxRecords)
	}
}

func TestAPI_Aggregate_Post_InvalidLevel(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := do(srv, http.MethodPost, "/api/aggregate",
		`{"enabled":true,"level":"bogus","max_records":10}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("POST /api/aggregate invalid level: status %d, want 400", w.Code)
	}
}

func TestAPI_Aggregate_Post_BadJSON(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := do(srv, http.MethodPost, "/api/aggregate", `{bad`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("POST /api/aggregate bad JSON: status %d, want 400", w.Code)
	}
}

func TestAPI_Aggregate_Post_ResponseIncludesConfig(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := do(srv, http.MethodPost, "/api/aggregate",
		`{"enabled":true,"level":"protocol","max_records":200}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", w.Code)
	}
	var resp aggregateResp
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Config.MaxRecords != 200 {
		t.Errorf("MaxRecords in response = %d, want 200", resp.Config.MaxRecords)
	}
}

// ── Method enforcement /api/aggregate ────────────────────────────────────────

func TestAPI_Aggregate_MethodNotAllowed(t *testing.T) {
	srv, _, _ := newTestServer(t)
	for _, method := range []string{http.MethodDelete, http.MethodPut, http.MethodPatch} {
		w := do(srv, method, "/api/aggregate", "")
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /api/aggregate: status %d, want 405", method, w.Code)
		}
	}
}

// ── POST /api/failure ─────────────────────────────────────────────────────────

func TestAPI_Failure_CPUOverload_Accepted(t *testing.T) {
	srv, _, _ := newTestServer(t)
	// Use 1-second duration so the background goroutine exits quickly.
	w := do(srv, http.MethodPost, "/api/failure", `{"type":"cpu-overload","duration":1}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("POST /api/failure cpu-overload: status %d, want 202\nbody: %s", w.Code, w.Body)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["type"] != "cpu-overload" {
		t.Errorf("response type = %v, want cpu-overload", resp["type"])
	}
	if _, ok := resp["duration"]; !ok {
		t.Error("response must include 'duration'")
	}
}

func TestAPI_Failure_DefaultDuration_UsedWhenZero(t *testing.T) {
	srv, _, _ := newTestServer(t)
	// Duration 0 → falls back to 60 s default; we only check the response shape.
	w := do(srv, http.MethodPost, "/api/failure", `{"type":"cpu-overload","duration":0}`)
	if w.Code != http.StatusAccepted {
		t.Errorf("POST /api/failure duration=0: status %d, want 202", w.Code)
	}
}

func TestAPI_Failure_UnknownType_BadRequest(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := do(srv, http.MethodPost, "/api/failure", `{"type":"disk-bomb","duration":1}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("POST /api/failure unknown type: status %d, want 400", w.Code)
	}
}

func TestAPI_Failure_BadJSON(t *testing.T) {
	srv, _, _ := newTestServer(t)
	w := do(srv, http.MethodPost, "/api/failure", `{bad`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("POST /api/failure bad JSON: status %d, want 400", w.Code)
	}
}

// ── Method enforcement /api/failure ──────────────────────────────────────────

func TestAPI_Failure_MethodNotAllowed(t *testing.T) {
	srv, _, _ := newTestServer(t)
	for _, method := range []string{http.MethodGet, http.MethodDelete, http.MethodPut} {
		w := do(srv, method, "/api/failure", "")
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /api/failure: status %d, want 405", method, w.Code)
		}
	}
}
