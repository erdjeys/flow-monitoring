// Router — core IP router connecting all network segments.
// Enables IP forwarding between servers-net, sensors-net, and mgmt-net.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os/exec"
	"strings"
)

func routes() []string {
	out, _ := exec.Command("ip", "route").Output()
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	result := make([]string, 0, len(lines))
	for _, l := range lines {
		if l != "" {
			result = append(result, l)
		}
	}
	return result
}

func interfaces() []string {
	out, _ := exec.Command("ip", "-brief", "addr").Output()
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	result := make([]string, 0, len(lines))
	for _, l := range lines {
		if l != "" {
			result = append(result, l)
		}
	}
	return result
}

func main() {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "operational",
			"role":   "core-router",
		})
	})

	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"role":       "core-router",
			"segments":   []string{"servers-net (10.0.1.0/24)", "sensors-net (10.0.2.0/24)", "mgmt-net (10.0.3.0/24)"},
			"routes":     routes(),
			"interfaces": interfaces(),
		})
	})

	log.Println("[ROUTER] Core router API on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
