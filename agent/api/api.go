// Package api exposes an HTTP control plane for problem injection,
// status reporting, live IPFIX template reconfiguration, and flow aggregation.
package api

import (
	"encoding/json"
	"log"
	"math"
	"net"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/flowmonitor/agent/aggregate"
	"github.com/flowmonitor/agent/flow"
)

// ── Interfaces ────────────────────────────────────────────────────────────────

// TemplateManager is implemented by protocols.IPFIXEncoder.
type TemplateManager interface {
	SetTemplate(fields []string) error
	CurrentTemplate() []string
	AvailableFields() []string
}

// AggregationManager is implemented by aggregate.Aggregator.
// It allows live reconfiguration of the flow aggregation engine.
type AggregationManager interface {
	GetConfig() aggregate.Config
	SetConfig(aggregate.Config)
	Stats() aggregate.Stats
}

// ── Server ────────────────────────────────────────────────────────────────────

// Server is the HTTP API server for the monitoring agent.
type Server struct {
	tracker *flow.Tracker
	ipfix   TemplateManager
	agg     AggregationManager
	mux     *http.ServeMux
}

func NewServer(t *flow.Tracker, ipfix TemplateManager, agg AggregationManager) *Server {
	s := &Server{tracker: t, ipfix: ipfix, agg: agg, mux: http.NewServeMux()}
	s.mux.HandleFunc("/api/problem", s.handleProblem)
	s.mux.HandleFunc("/api/status", s.handleStatus)
	s.mux.HandleFunc("/api/ipfix/template", s.handleIPFIXTemplate)
	s.mux.HandleFunc("/api/aggregate", s.handleAggregate)
	s.mux.HandleFunc("/api/failure", s.handleFailure)
	return s
}

func (s *Server) Listen(addr string) error {
	return http.ListenAndServe(addr, s.mux)
}

// ── Problem injection ─────────────────────────────────────────────────────────

type problemReq struct {
	SrcIP      string  `json:"src_ip"`
	DstIP      string  `json:"dst_ip"`
	SrcPort    uint16  `json:"src_port"`
	DstPort    uint16  `json:"dst_port"`
	Protocol   uint8   `json:"protocol"`
	PacketLoss float64 `json:"packet_loss"`
	LatencyMs  int     `json:"latency_ms"`
}

func (s *Server) handleProblem(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req problemReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		key := flow.Key{
			SrcPort:  req.SrcPort,
			DstPort:  req.DstPort,
			Protocol: req.Protocol,
		}
		if ip := net.ParseIP(req.SrcIP).To4(); ip != nil {
			copy(key.SrcIP[:], ip)
		}
		if ip := net.ParseIP(req.DstIP).To4(); ip != nil {
			copy(key.DstIP[:], ip)
		}
		s.tracker.InjectProblem(key, flow.Problem{
			PacketLoss:   req.PacketLoss,
			ExtraLatency: time.Duration(req.LatencyMs) * time.Millisecond,
		})
		w.WriteHeader(http.StatusNoContent)

	case http.MethodDelete:
		s.tracker.ClearProblems()
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ── Status ────────────────────────────────────────────────────────────────────

type statusResp struct {
	ActiveFlows       int            `json:"active_flows"`
	OverflowEvictions uint64         `json:"overflow_evictions"`
	IPFIXTemplate     []string       `json:"ipfix_template"`
	Aggregation       aggregate.Stats `json:"aggregation"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	st := s.tracker.Stats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(statusResp{
		ActiveFlows:       st.ActiveFlows,
		OverflowEvictions: st.OverflowEvictions,
		IPFIXTemplate:     s.ipfix.CurrentTemplate(),
		Aggregation:       s.agg.Stats(),
	})
}

// ── IPFIX template management ─────────────────────────────────────────────────

type templateResp struct {
	Active    []string `json:"active"`
	Available []string `json:"available"`
}

func (s *Server) handleIPFIXTemplate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(templateResp{
			Active:    s.ipfix.CurrentTemplate(),
			Available: s.ipfix.AvailableFields(),
		})
	case http.MethodPost:
		var req struct {
			Fields []string `json:"fields"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.ipfix.SetTemplate(req.Fields); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"active": s.ipfix.CurrentTemplate()})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ── Failure simulation ────────────────────────────────────────────────────────
//
//   POST /api/failure  {"type":"cpu-overload","duration":60}
//
//   Spawns a CPU-burning goroutine for the requested number of seconds.
//   The agent's /proc/stat sampler picks up the load spike within 5 s and stamps
//   the elevated cpu_load value into all subsequent IPFIX flow records.
//   The Grafana "CPU Overload" alert fires when cpu_load exceeds 85 %.

func (s *Server) handleFailure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Type     string `json:"type"`
		Duration int    `json:"duration"` // seconds
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	dur := time.Duration(req.Duration) * time.Second
	if dur <= 0 {
		dur = 60 * time.Second
	}
	switch req.Type {
	case "cpu-overload":
		go burnCPU(dur)
		log.Printf("[FAILURE] CPU overload simulation started for %s", dur)
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"type":     "cpu-overload",
			"duration": dur.String(),
			"note":     "busy loop running; cpu_load field will spike in next IPFIX export",
		})
	default:
		http.Error(w, `unknown failure type; supported: "cpu-overload"`, http.StatusBadRequest)
	}
}

// burnCPU saturates all available CPU cores for the given duration so that
// /proc/stat reports a load spike that is reflected in outgoing IPFIX records.
// One goroutine per logical CPU is spawned; they all stop when the deadline hits.
func burnCPU(duration time.Duration) {
	deadline := time.Now().Add(duration)
	n := runtime.NumCPU()
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				x := 1.0
				for i := 0; i < 5000; i++ {
					x = math.Sqrt(x + float64(i))
				}
				_ = x
			}
		}()
	}
	wg.Wait()
}

// ── Flow aggregation ──────────────────────────────────────────────────────────
//
//   GET  /api/aggregate
//        Returns current configuration and cumulative statistics.
//
//   POST /api/aggregate
//        {"enabled":true,"level":"protocol","max_records":100}
//        Hot-reconfigures the aggregator; takes effect on the next export batch.
//        level: "none" | "protocol" | "host_pair"

type aggregateResp struct {
	Config aggregate.Config `json:"config"`
	Stats  aggregate.Stats  `json:"stats"`
}

func (s *Server) handleAggregate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(aggregateResp{
			Config: s.agg.GetConfig(),
			Stats:  s.agg.Stats(),
		})

	case http.MethodPost:
		// Start from current config so the caller can PATCH individual fields.
		cfg := s.agg.GetConfig()
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Validate level.
		switch cfg.Level {
		case aggregate.LevelNone, aggregate.LevelProtocol, aggregate.LevelHostPair:
			// OK
		default:
			http.Error(w, `level must be "none", "protocol", or "host_pair"`, http.StatusBadRequest)
			return
		}
		s.agg.SetConfig(cfg)
		json.NewEncoder(w).Encode(aggregateResp{
			Config: s.agg.GetConfig(),
			Stats:  s.agg.Stats(),
		})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
