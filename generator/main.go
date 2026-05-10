// Generator drives all inter-device traffic for the network simulation
// and exposes an on-demand attack API on port 8081.
package main

import (
	"encoding/json"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/flowmonitor/generator/attacks"
	"github.com/flowmonitor/generator/failures"
	"github.com/flowmonitor/generator/flowexp"
	"github.com/flowmonitor/generator/profiles"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

type attackRequest struct {
	Type     string `json:"type"`
	Target   string `json:"target"`
	Duration int    `json:"duration"` // seconds; 0 = use default
}

func main() {
	collectorAddr := env("COLLECTOR_ADDR", "10.0.3.50:2055")
	serverAddr        := env("SERVER_ADDR",        "http://10.0.1.10:8080")
	iface         := env("INTERFACE",      "eth0")
	apiPort       := env("API_PORT",       "8081")

	log.Printf("Generator starting | collector=%s", collectorAddr)

	time.Sleep(10 * time.Second)

	exp, err := flowexp.New(collectorAddr)
	if err != nil {
		log.Fatalf("flowexp: %v", err)
	}
	defer exp.Close()

	go profiles.RunCommand(serverAddr, exp)
	go profiles.RunStatusReport(serverAddr, exp)
	go profiles.RunFTP(exp)
	go profiles.RunVoIP(exp)
	go profiles.RunSSH(exp)
	go profiles.RunNetInfra(exp)
	go profiles.RunICMP(exp)
	go profiles.RunSensorTraffic(exp)

	http.HandleFunc("/api/attack", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req attackRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if req.Target == "" {
			req.Target = "172.20.0.10"
		}
		dur := time.Duration(req.Duration) * time.Second
		if dur == 0 {
			dur = 30 * time.Second
		}

		switch req.Type {
		case "synflood":
			go attacks.SYNFlood(iface, req.Target, "10.0.1.40", 80, dur, exp)
		case "portscan":
			go attacks.PortScan(req.Target, 1, 1024, exp)
		case "udpflood":
			go attacks.UDPFlood(req.Target, 53, dur, exp)
		case "lateral":
			go attacks.LateralMovement(req.Target, dur, exp)
		default:
			http.Error(w, "unknown attack type", http.StatusBadRequest)
			return
		}

		log.Printf("Attack triggered: type=%s target=%s duration=%s", req.Type, req.Target, dur)
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"status": "started", "type": req.Type})
	})

	http.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "operational"})
	})

	// ── Cache-overflow stress test ────────────────────────────────────────────
	//
	// POST /api/test/cache-overflow  {"unique_sources": 50000}
	//
	// Simulates a hardware router whose NetFlow cache filled up and is now
	// bulk-dumping all accumulated flow records to the collector. Each record
	// has a distinct source IP, so the CMDB must absorb a large spike of new
	// asset discoveries. Use this to verify:
	//   1. The collector handles high-volume flow bursts without data loss.
	//   2. The CMDB correctly registers thousands of new "shadow" IPs.
	//   3. The agent's flow cache eviction fires if MAX_FLOWS is hit.
	http.HandleFunc("/api/test/cache-overflow", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			UniqueSources int `json:"unique_sources"`
		}
		req.UniqueSources = 50_000 // default
		json.NewDecoder(r.Body).Decode(&req)
		if req.UniqueSources <= 0 {
			req.UniqueSources = 50_000
		}
		if req.UniqueSources > 500_000 {
			req.UniqueSources = 500_000
		}
		total := req.UniqueSources

		go func() {
			log.Printf("[OVERFLOW-TEST] starting: %d unique-source flows → collector", total)
			dstIP := net.ParseIP("10.0.1.10").To4()
			batch := make([]flowexp.Record, 0, 30)
			sent := 0

			for i := 0; i < total; i++ {
				// Use 198.51.100.0/22 (RFC 5737 documentation range) to avoid
				// clashing with real infrastructure IPs in the CMDB.
				srcIP := net.IPv4(
					198,
					byte(50+i>>16&0x0F),
					byte(i>>8&0xFF),
					byte(i&0xFF),
				).To4()
				batch = append(batch, flowexp.Record{
					SrcIP:    srcIP,
					DstIP:    dstIP,
					SrcPort:  uint16(1024 + rand.Intn(60000)),
					DstPort:  80,
					Protocol: 6,
					TCPFlags: 0x02,
					Packets:  1,
					Bytes:    60,
				})
				if len(batch) == 30 {
					exp.Send(batch)
					batch = batch[:0]
					sent += 30
					if sent%9000 == 0 {
						log.Printf("[OVERFLOW-TEST] sent %d/%d flows", sent, total)
						time.Sleep(time.Millisecond) // yield briefly
					}
				}
			}
			if len(batch) > 0 {
				exp.Send(batch)
				sent += len(batch)
			}
			log.Printf("[OVERFLOW-TEST] complete: %d flows sent to collector", sent)
		}()

		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":         "started",
			"unique_sources": total,
			"description":    "bulk-dumping unique flows to simulate router cache overflow",
		})
	})

	// ── Failure simulation ────────────────────────────────────────────────────
	//
	// POST /api/failure  {"type":"disconnect","target":"10.0.2.30","duration":120}
	//
	// Simulates a network failure by silencing all flows involving the target IP
	// for the specified duration. The CMDB's last_seen will age out and any
	// "device offline" alert in Grafana will fire after 5 minutes of silence.
	//
	// GET /api/failure  → lists currently active failure states
	http.HandleFunc("/api/failure", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			active := failures.Default.Active()
			out := make(map[string]string, len(active))
			for ip, rem := range active {
				out[ip] = rem.Round(time.Second).String()
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"active_disconnections": out,
			})

		case http.MethodPost:
			var req struct {
				Type     string `json:"type"`
				Target   string `json:"target"`
				Duration int    `json:"duration"` // seconds
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if req.Type != "disconnect" {
				http.Error(w, `only type "disconnect" is supported on this endpoint`, http.StatusBadRequest)
				return
			}
			ip := net.ParseIP(req.Target)
			if ip == nil {
				http.Error(w, "invalid target IP", http.StatusBadRequest)
				return
			}
			dur := time.Duration(req.Duration) * time.Second
			if dur <= 0 {
				dur = 120 * time.Second
			}
			failures.Default.Disconnect(ip, dur)
			log.Printf("[FAILURE] disconnect %s for %s", req.Target, dur)
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":   "disconnected",
				"target":   req.Target,
				"duration": dur.String(),
			})

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	log.Printf("Attack API listening on :%s", apiPort)
	log.Fatal(http.ListenAndServe(":"+apiPort, nil))
}
