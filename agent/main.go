package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/flowmonitor/agent/aggregate"
	"github.com/flowmonitor/agent/api"
	"github.com/flowmonitor/agent/capture"
	"github.com/flowmonitor/agent/export"
	"github.com/flowmonitor/agent/flow"
	"github.com/flowmonitor/agent/protocols"
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

// ifaceIP returns the first IPv4 address assigned to iface.
func ifaceIP(iface string) net.IP {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return net.IPv4zero
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return net.IPv4zero
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if v4 := ip.To4(); v4 != nil {
			return v4
		}
	}
	return net.IPv4zero
}

// cpuSampler reads /proc/stat every interval and updates the tracker's
// CPU load field so it is stamped into new IPFIX flows.
func cpuSampler(tracker *flow.Tracker, interval time.Duration) {
	var prevTotal, prevIdle uint64

	sample := func() {
		data, err := os.ReadFile("/proc/stat")
		if err != nil {
			return
		}
		var user, nice, system, idle, iowait, irq, softirq uint64
		if _, err := fmt.Sscanf(string(data),
			"cpu %d %d %d %d %d %d %d",
			&user, &nice, &system, &idle, &iowait, &irq, &softirq); err != nil {
			return
		}
		total := user + nice + system + idle + iowait + irq + softirq
		idleAll := idle + iowait
		deltaTotal := total - prevTotal
		deltaIdle := idleAll - prevIdle
		prevTotal = total
		prevIdle = idleAll
		if deltaTotal == 0 {
			return
		}
		pct := uint8((deltaTotal - deltaIdle) * 100 / deltaTotal)
		tracker.SetCpuLoad(pct)
	}

	sample() // prime baseline
	t := time.NewTicker(interval)
	defer t.Stop()
	for range t.C {
		sample()
	}
}

func main() {
	iface := env("INTERFACE", "eth0")
	collectorAddr := env("COLLECTOR_ADDR", "localhost:2055")
	ipfixAddr := env("IPFIX_ADDR", "localhost:4739")
	sflowAddr := env("SFLOW_ADDR", "localhost:6343")
	iedAPI := env("IED_API", "")
	apiPort := env("API_PORT", "8080")
	activeTo := time.Duration(envInt("ACTIVE_TIMEOUT", 60)) * time.Second
	inactiveTo := time.Duration(envInt("INACTIVE_TIMEOUT", 15)) * time.Second
	sflowRate := uint32(envInt("SFLOW_RATE", 512))
	maxFlows := envInt("MAX_FLOWS", 100_000)
	aggMaxRecords := envInt("AGG_MAX_RECORDS", 200)

	agentIP := ifaceIP(iface)
	log.Printf("flow-monitoring agent | iface=%s ip=%s maxFlows=%d aggMax=%d",
		iface, agentIP, maxFlows, aggMaxRecords)

	// ── Exporters ─────────────────────────────────────────────────────────────
	nfExp, err := export.New(collectorAddr)
	if err != nil {
		log.Fatalf("netflow exporter: %v", err)
	}
	defer nfExp.Close()

	ipfixExp, err := export.New(ipfixAddr)
	if err != nil {
		log.Fatalf("ipfix exporter: %v", err)
	}
	defer ipfixExp.Close()

	sflowExp, err := export.New(sflowAddr)
	if err != nil {
		log.Fatalf("sflow exporter: %v", err)
	}
	defer sflowExp.Close()

	// ── Encoders & samplers ───────────────────────────────────────────────────
	nfEnc := protocols.NewNetFlow(nfExp)
	ipfixEnc := protocols.NewIPFIX(ipfixExp)
	sflowSampler := protocols.NewSFlow(sflowExp, sflowRate, agentIP)

	// ── Flow aggregator (narrow-channel optimisation) ─────────────────────────
	agg := aggregate.New(aggregate.Config{
		Enabled:    true,
		Level:      aggregate.LevelProtocol,
		MaxRecords: aggMaxRecords,
	})

	// ── Flow tracker ──────────────────────────────────────────────────────────
	tracker := flow.NewTracker(activeTo, inactiveTo, maxFlows)
	tracker.SetIEDAPI(iedAPI)

	tracker.OnExport(func(records []*flow.Record) {
		// Apply aggregation before encoding — reduces wire volume on narrow links.
		processed := agg.Process(records)

		if err := nfEnc.Export(processed); err != nil {
			log.Printf("netflow export: %v", err)
		}
		if err := ipfixEnc.Export(processed); err != nil {
			log.Printf("ipfix export: %v", err)
		}
	})

	go tracker.Run()
	go cpuSampler(tracker, 5*time.Second)

	// ── HTTP control plane ────────────────────────────────────────────────────
	srv := api.NewServer(tracker, ipfixEnc, agg)
	go func() {
		log.Printf("API listening on :%s", apiPort)
		if err := srv.Listen(":" + apiPort); err != nil {
			log.Printf("API error: %v", err)
		}
	}()

	// ── Packet capture ────────────────────────────────────────────────────────
	cap, err := capture.New(iface)
	if err != nil {
		log.Fatalf("capture on %s: %v", iface, err)
	}
	defer cap.Close()

	log.Printf("capturing | NetFlow→%s IPFIX→%s sFlow→%s", collectorAddr, ipfixAddr, sflowAddr)

	for pkt := range cap.Packets() {
		tracker.Process(pkt)
		sflowSampler.Sample(pkt)
	}
}
