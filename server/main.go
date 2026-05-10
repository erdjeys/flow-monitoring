// Control server — receives device reports, issues tasks, provides status overview.
package main

import (
	"encoding/json"
	"log"
	"math/rand"
	"net/http"
	"os"
	"sync"
	"time"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

type Order struct {
	ID       string    `json:"id"`
	Priority string    `json:"priority"`
	Target   string    `json:"target"`
	Action   string    `json:"action"`
	IssuedAt time.Time `json:"issued_at"`
}

type StatusReport struct {
	UnitID    string    `json:"unit_id"`
	Status    string    `json:"status"`
	Location  string    `json:"location"`
	Timestamp time.Time `json:"timestamp"`
}

var (
	mu     sync.Mutex
	orders = []Order{
		{ID: "ORD-001", Priority: "HIGH", Target: "NODE-7", Action: "SCAN", IssuedAt: time.Now()},
		{ID: "ORD-002", Priority: "MEDIUM", Target: "NODE-A", Action: "MONITOR", IssuedAt: time.Now()},
		{ID: "ORD-003", Priority: "LOW", Target: "ZONE-B", Action: "CHECK", IssuedAt: time.Now()},
		{ID: "ORD-004", Priority: "HIGH", Target: "ZONE-4491", Action: "INSPECT", IssuedAt: time.Now()},
		{ID: "ORD-005", Priority: "MEDIUM", Target: "NODE-2", Action: "UPDATE_CONFIG", IssuedAt: time.Now()},
	}
	reports []StatusReport
)

func main() {
	port := env("API_PORT", "8080")
	mux := http.NewServeMux()

	mux.HandleFunc("/api/orders", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"orders": orders, "count": len(orders)})
	})

	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var rep StatusReport
		if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		rep.Timestamp = time.Now()
		mu.Lock()
		reports = append(reports, rep)
		if len(reports) > 200 {
			reports = reports[len(reports)-200:]
		}
		mu.Unlock()
		log.Printf("[SRV] STATUS from %s: %s @ %s", rep.UnitID, rep.Status, rep.Location)
		w.WriteHeader(http.StatusAccepted)
	})

	mux.HandleFunc("/api/overview", func(w http.ResponseWriter, r *http.Request) {
		levels := []string{"OK", "WARNING", "CRITICAL"}
		mu.Lock()
		units := len(reports)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"timestamp":      time.Now(),
			"alert_level":    levels[rand.Intn(len(levels))],
			"active_units":   units,
			"pending_orders": len(orders),
			"zone":           "ZONE-6",
		})
	})

	mux.HandleFunc("/api/alert", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			return
		}
		var alert map[string]interface{}
		json.NewDecoder(r.Body).Decode(&alert)
		log.Printf("[SRV] ALERT: %v", alert)
		w.WriteHeader(http.StatusAccepted)
	})

	mux.HandleFunc("/api/reports", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		n := len(reports)
		if n > 20 {
			n = 20
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"reports": reports[len(reports)-n:], "total": len(reports)})
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "operational", "unit": "control-server"})
	})

	log.Printf("[SRV] Control server on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
