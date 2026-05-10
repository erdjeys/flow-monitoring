package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"

	"github.com/flowmonitor/collector/anomaly"
	"github.com/flowmonitor/collector/cmdb"
	"github.com/flowmonitor/collector/influx"
	"github.com/flowmonitor/collector/parser"
	"github.com/flowmonitor/collector/responder"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

func main() {
	influxURL := env("INFLUXDB_URL", "http://localhost:8086")
	token := env("INFLUXDB_TOKEN", "")
	org := env("INFLUXDB_ORG", "flowmonitor")
	bucket := env("INFLUXDB_BUCKET", "flows")
	postgresDSN := env("POSTGRES_DSN", "postgres://cmdb:cmdb123@localhost:5432/cmdb?sslmode=disable")

	nfPort := env("NETFLOW_PORT", "2055")
	ipfixPort := env("IPFIX_PORT", "4739")
	sflowPort := env("SFLOW_PORT", "6343")
	httpPort := env("HTTP_PORT", "8079")
	agentAPI := env("AGENT_API", "http://10.0.3.20:8080")

	writer := influx.NewWriter(influxURL, token, org, bucket)
	defer writer.Close()

	store, err := cmdb.New(postgresDSN)
	if err != nil {
		log.Fatalf("cmdb init: %v", err)
	}
	defer store.Close()

	detector := anomaly.NewDetector()
	resp := responder.New(agentAPI)

	// Persist every alert to PostgreSQL and trigger the automatic response.
	detector.OnAlert(func(a anomaly.Alert) {
		if err := store.PersistAlert(string(a.AlertType), a.Severity, a.SrcIP, a.DstIP, a.Detail); err != nil {
			log.Printf("persist alert: %v", err)
		}
		resp.OnAlert(a)
	})

	// Single handler fans each decoded flow to all three subsystems.
	handle := func(r *influx.FlowRecord) {
		writer.WriteFlow(r)
		store.Observe(r)
		detector.Observe(r)
	}

	log.Printf("flow collector | NetFlow:%s IPFIX:%s sFlow:%s → influx:%s http::%s",
		nfPort, ipfixPort, sflowPort, influxURL, httpPort)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := parser.ListenNetFlow(":"+nfPort, handle); err != nil {
			log.Printf("netflow listener: %v", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := parser.ListenIPFIX(":"+ipfixPort, handle); err != nil {
			log.Printf("ipfix listener: %v", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := parser.ListenSFlow(":"+sflowPort, handle); err != nil {
			log.Printf("sflow listener: %v", err)
		}
	}()

	// ── Inventory & Anomaly HTTP API ──────────────────────────────────────────
	//
	//   GET /health                       → {"status":"ok"}
	//
	//   GET /api/assets                   → full inventory (stealth-score descending)
	//   GET /api/assets?shadow=70         → only assets with stealth_score ≥ 70
	//   GET /api/topology                 → src→dst traffic matrix (bytes desc)
	//
	//   GET /api/alerts                   → recent anomaly alerts (newest last)
	//   GET /api/alerts?type=PORT_SCAN    → filtered by alert type

	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/api/assets", func(w http.ResponseWriter, r *http.Request) {
		var assets []cmdb.Asset
		var err error

		if minStr := r.URL.Query().Get("shadow"); minStr != "" {
			min, _ := strconv.Atoi(minStr)
			if min == 0 {
				min = 70 // default shadow threshold
			}
			assets, err = store.ShadowAssets(min)
		} else {
			assets, err = store.Assets()
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if assets == nil {
			assets = []cmdb.Asset{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(assets)
	})

	mux.HandleFunc("/api/topology", func(w http.ResponseWriter, r *http.Request) {
		entries, err := store.Topology()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if entries == nil {
			entries = []cmdb.TopologyEntry{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entries)
	})

	mux.HandleFunc("/api/alerts", func(w http.ResponseWriter, r *http.Request) {
		all := detector.Alerts()

		// Optional filter by alert type.
		if t := r.URL.Query().Get("type"); t != "" {
			filtered := all[:0]
			for _, a := range all {
				if string(a.AlertType) == t {
					filtered = append(filtered, a)
				}
			}
			all = filtered
		}

		if all == nil {
			all = []anomaly.Alert{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(all)
	})

	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Printf("Inventory+Alerts API on :%s", httpPort)
		if err := http.ListenAndServe(":"+httpPort, mux); err != nil {
			log.Printf("inventory HTTP: %v", err)
		}
	}()

	wg.Wait()
}
