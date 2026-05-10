// Field device — generic sensor node (GPS, Radar, Comms).
// Serves a status/telemetry API polled by the monitoring agent.
// Periodically pushes reports to the control server.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

type Status struct {
	DeviceID         string  `json:"device_id"`
	DeviceType       string  `json:"device_type"`
	SignalStrength    int8    `json:"signal_strength"`
	EncryptionStatus uint8   `json:"encryption_status"`
	// SensorStatus encodes the overall health of this device:
	//   0 = OK      (signal > -80 dBm, encryption active)
	//   1 = WARNING (signal -80…-90 dBm, or encryption disabled)
	//   2 = ERROR   (signal < -90 dBm — link quality critical)
	SensorStatus     uint8   `json:"sensor_status"`
	BatteryPct       int     `json:"battery_pct"`
	Uptime           float64 `json:"uptime_s"`
	Timestamp        string  `json:"timestamp"`
}

// sensorStatus derives a 3-state health code from signal and encryption.
func sensorStatus(sig int8, enc uint8) uint8 {
	if sig < -90 {
		return 2 // ERROR
	}
	if sig < -80 || enc == 0 {
		return 1 // WARNING
	}
	return 0 // OK
}

var (
	mu         sync.RWMutex
	deviceID   string
	deviceType string
	sigBase    int8
	encStatus  uint8
	startTime  = time.Now()
)

func main() {
	deviceID = env("DEVICE_ID", "SENSOR-001")
	deviceType = env("DEVICE_TYPE", "GPS")
	port := env("API_PORT", "9000")
	serverAddr := env("SERVER_ADDR", "http://172.20.0.10:8080")
	sigBase = int8(envInt("SIGNAL_BASE", -65))
	encStatus = uint8(envInt("ENCRYPTION_STATUS", 1))

	go func() {
		for t := range time.Tick(5 * time.Second) {
			drift := int8(math.Round(3 * math.Sin(float64(t.Unix()) / 30.0)))
			mu.Lock()
			sigBase = int8(int(sigBase) + int(drift))
			if sigBase > -40 {
				sigBase = -40
			}
			if sigBase < -95 {
				sigBase = -95
			}
			mu.Unlock()
		}
	}()

	go func() {
		time.Sleep(10 * time.Second)
		for range time.Tick(time.Duration(60+rand.Intn(120)) * time.Second) {
			sendReport(serverAddr)
		}
	}()

	mux := http.NewServeMux()

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		sig := sigBase
		enc := encStatus
		mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Status{
			DeviceID:         deviceID,
			DeviceType:       deviceType,
			SignalStrength:    sig,
			EncryptionStatus: enc,
			SensorStatus:     sensorStatus(sig, enc),
			BatteryPct:       60 + rand.Intn(40),
			Uptime:           time.Since(startTime).Seconds(),
			Timestamp:        time.Now().UTC().Format(time.RFC3339),
		})
	})

	mux.HandleFunc("/status/set", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			SignalStrength    *int8  `json:"signal_strength"`
			EncryptionStatus *uint8 `json:"encryption_status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		if req.SignalStrength != nil {
			sigBase = *req.SignalStrength
		}
		if req.EncryptionStatus != nil {
			encStatus = *req.EncryptionStatus
		}
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("/telemetry", func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		sig := sigBase
		mu.RUnlock()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"device_id":   deviceID,
			"device_type": deviceType,
			"timestamp":   time.Now(),
			"readings":    generateReadings(deviceType, sig),
		})
	})

	mux.HandleFunc("/command", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			return
		}
		var cmd map[string]string
		json.NewDecoder(r.Body).Decode(&cmd)
		log.Printf("[%s] Command: %v", deviceID, cmd)
		json.NewEncoder(w).Encode(map[string]string{"status": "ack", "device": deviceID})
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	log.Printf("[%s] %s sensor on :%s", deviceID, deviceType, port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

func generateReadings(dt string, signal int8) map[string]interface{} {
	switch dt {
	case "GPS":
		return map[string]interface{}{
			"gps_lock":    rand.Intn(2) == 0,
			"proximity_m": fmt.Sprintf("%.1f", 50+rand.Float64()*200),
			"signal_dbm":  int(signal),
		}
	case "RADAR":
		return map[string]interface{}{
			"sweep_range_km":   fmt.Sprintf("%.1f", 5+rand.Float64()*45),
			"targets_detected": rand.Intn(5),
			"bearing_deg":      rand.Intn(360),
			"elevation_m":      rand.Intn(3000),
		}
	case "COMMS":
		return map[string]interface{}{
			"channel":       rand.Intn(16) + 1,
			"frequency_mhz": fmt.Sprintf("%.2f", 148.5+rand.Float64()*3),
			"squelch":       rand.Intn(10),
			"signal_dbm":    int(signal),
		}
	default:
		return map[string]interface{}{"signal_dbm": int(signal)}
	}
}

func sendReport(serverAddr string) {
	mu.RLock()
	sig := sigBase
	enc := encStatus
	mu.RUnlock()

	body, _ := json.Marshal(map[string]string{
		"unit_id":  deviceID,
		"status":   "OPERATIONAL",
		"location": fmt.Sprintf("type=%s signal=%ddBm enc=%d", deviceType, sig, enc),
	})
	resp, err := http.Post(serverAddr+"/api/status", "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("[%s] report error: %v", deviceID, err)
		return
	}
	resp.Body.Close()
}
