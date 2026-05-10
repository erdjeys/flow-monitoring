// Switch — layer-2 access switch for a network segment.
package main

import (
	"encoding/json"
	"log"
	"math/rand"
	"net/http"
	"os"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	id := env("SWITCH_ID", "SW-01")
	segment := env("SEGMENT", "servers")

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "operational",
			"unit":    id,
			"segment": segment,
		})
	})

	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		const totalPorts = 24
		active := 4 + rand.Intn(8)
		ports := make([]map[string]interface{}, totalPorts)
		for i := range ports {
			state := "down"
			if i < active {
				state = "up"
			}
			ports[i] = map[string]interface{}{
				"port":  i + 1,
				"state": state,
				"speed": "1Gbps",
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"switch_id":   id,
			"segment":     segment,
			"total_ports": totalPorts,
			"active":      active,
			"ports":       ports,
		})
	})

	log.Printf("[SWITCH] %s (%s) API on :8080", id, segment)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
