// Package profiles simulates normal network traffic via synthetic NetFlow records.
package profiles

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"time"

	"github.com/flowmonitor/generator/failures"
	"github.com/flowmonitor/generator/flowexp"
)

// sendIfUp filters out any records whose source or destination IP is currently
// in a simulated disconnected state, then sends the remaining records.
// This makes "port disconnect" simulation transparent to each profile goroutine.
func sendIfUp(exp *flowexp.Exporter, records []flowexp.Record) {
	filtered := records[:0]
	for _, r := range records {
		if !failures.Default.IsDisconnected(r.SrcIP) &&
			!failures.Default.IsDisconnected(r.DstIP) {
			filtered = append(filtered, r)
		}
	}
	if len(filtered) > 0 {
		exp.Send(filtered)
	}
}

// ── Real container IPs ────────────────────────────────────────────────────────

var (
	// servers-net (10.0.1.0/24)
	ipServer        = net.ParseIP("10.0.1.10").To4()
	ipSwitchServers = net.ParseIP("10.0.1.2").To4()

	// sensors-net (10.0.2.0/24)
	ipSens          = net.ParseIP("10.0.2.30").To4()
	ipSwitchSensors = net.ParseIP("10.0.2.2").To4()

	// mgmt-net (10.0.3.0/24)
	ipCollector = net.ParseIP("10.0.3.50").To4()

	// router — one IP per segment
	ipRouterServers = net.ParseIP("10.0.1.254").To4()
	ipRouterSensors = net.ParseIP("10.0.2.254").To4()
	ipRouterMgmt    = net.ParseIP("10.0.3.254").To4()
)

// ── Virtual participants (flowexp only — no real container) ───────────────────

var (
	ipWSAlpha   = net.ParseIP("10.0.1.21").To4() // workstation A (servers-net)
	ipWSBravo   = net.ParseIP("10.0.1.22").To4() // workstation B (servers-net)
	ipWSCharlie = net.ParseIP("10.0.1.23").To4() // workstation C / admin (servers-net)
	ipVoIPGW    = net.ParseIP("10.0.1.15").To4() // VoIP gateway (servers-net)
	ipDNS       = net.ParseIP("10.0.3.17").To4() // DNS server (mgmt-net)
	ipNTP       = net.ParseIP("10.0.3.18").To4() // NTP server (mgmt-net)
	ipLogSrv    = net.ParseIP("10.0.3.19").To4() // syslog server (mgmt-net)
)

var allIPs = []net.IP{
	ipWSAlpha, ipWSBravo, ipWSCharlie,
	ipServer, ipSens,
	ipSwitchServers, ipSwitchSensors,
}

var httpClient = &http.Client{Timeout: 5 * time.Second}

func randPort() uint16 { return uint16(40000 + rand.Intn(20000)) }
func jitter(base, spread int) time.Duration {
	return time.Duration(base+rand.Intn(spread)) * time.Second
}

// RunCommand simulates workstations querying the server.
func RunCommand(serverAddr string, exp *flowexp.Exporter) {
	srcs := []net.IP{ipWSAlpha, ipWSBravo}
	endpoints := []string{"/api/orders", "/api/overview", "/api/reports"}
	for {
		src := srcs[rand.Intn(len(srcs))]
		ep := endpoints[rand.Intn(len(endpoints))]

		resp, err := httpClient.Get(serverAddr + ep)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}

		pkts := uint32(5 + rand.Intn(15))
		sendIfUp(exp, []flowexp.Record{{
			SrcIP:    src,
			DstIP:    ipServer,
			SrcPort:  randPort(),
			DstPort:  8080,
			Protocol: 6,
			TCPFlags: 0x18,
			Packets:  pkts,
			Bytes:    pkts * uint32(150+rand.Intn(800)),
		}})

		time.Sleep(jitter(45, 90))
	}
}

// RunFTP simulates document transfers (TCP/21 control + TCP/20 data).
func RunFTP(exp *flowexp.Exporter) {
	srcs := []net.IP{ipWSBravo, ipWSCharlie}
	for {
		src := srcs[rand.Intn(len(srcs))]
		fileSize := uint32(50000 + rand.Intn(2000000))
		filePkts := fileSize / 1400

		log.Printf("[FTP] transfer %.1f KB", float64(fileSize)/1024)

		sendIfUp(exp, []flowexp.Record{{
			SrcIP: src, DstIP: ipServer,
			SrcPort: randPort(), DstPort: 21,
			Protocol: 6, TCPFlags: 0x18,
			Packets: uint32(8 + rand.Intn(12)), Bytes: uint32(300 + rand.Intn(400)),
		}})

		dataPort := randPort()
		sendIfUp(exp, []flowexp.Record{
			{SrcIP: ipServer, DstIP: src, SrcPort: 20, DstPort: dataPort,
				Protocol: 6, TCPFlags: 0x18, Packets: filePkts, Bytes: fileSize},
			{SrcIP: src, DstIP: ipServer, SrcPort: dataPort, DstPort: 20,
				Protocol: 6, TCPFlags: 0x10, Packets: filePkts / 2, Bytes: filePkts / 2 * 40},
		})

		time.Sleep(jitter(300, 300))
	}
}

// RunVoIP simulates SIP-signalled voice calls with G.711 RTP streams.
func RunVoIP(exp *flowexp.Exporter) {
	pairs := [][2]net.IP{
		{ipWSAlpha, ipWSBravo},
		{ipWSBravo, ipWSCharlie},
		{ipWSAlpha, ipWSCharlie},
	}
	for {
		pair := pairs[rand.Intn(len(pairs))]
		caller, callee := pair[0], pair[1]
		duration := 30 + rand.Intn(90)
		rtpPkts := uint32(50 * duration)

		sendIfUp(exp, []flowexp.Record{
			{SrcIP: caller, DstIP: ipVoIPGW, SrcPort: randPort(), DstPort: 5060,
				Protocol: 17, Packets: 2, Bytes: 900},
			{SrcIP: ipVoIPGW, DstIP: caller, SrcPort: 5060, DstPort: randPort(),
				Protocol: 17, Packets: 2, Bytes: 600},
			{SrcIP: caller, DstIP: callee, SrcPort: 5004, DstPort: 5004,
				Protocol: 17, Packets: rtpPkts, Bytes: rtpPkts * 172},
			{SrcIP: callee, DstIP: caller, SrcPort: 5004, DstPort: 5004,
				Protocol: 17, Packets: rtpPkts, Bytes: rtpPkts * 172},
			{SrcIP: caller, DstIP: ipVoIPGW, SrcPort: randPort(), DstPort: 5060,
				Protocol: 17, Packets: 2, Bytes: 400},
		})

		log.Printf("[VOIP] call %v→%v duration=%ds", caller, callee, duration)
		time.Sleep(jitter(600, 600))
	}
}

// RunSSH simulates admin maintenance sessions to the server.
func RunSSH(exp *flowexp.Exporter) {
	for {
		sessionBytes := uint32(5000 + rand.Intn(50000))
		pkts := sessionBytes / 500

		sendIfUp(exp, []flowexp.Record{
			{SrcIP: ipWSCharlie, DstIP: ipServer, SrcPort: randPort(), DstPort: 22,
				Protocol: 6, TCPFlags: 0x18, Packets: pkts, Bytes: sessionBytes},
			{SrcIP: ipServer, DstIP: ipWSCharlie, SrcPort: 22, DstPort: randPort(),
				Protocol: 6, TCPFlags: 0x18, Packets: pkts * 2, Bytes: sessionBytes / 2},
		})

		log.Printf("[SSH] admin session → server")
		time.Sleep(jitter(600, 600))
	}
}

// RunNetInfra exports background DNS/NTP/Syslog flows, showing router hops for cross-segment traffic.
func RunNetInfra(exp *flowexp.Exporter) {
	for {
		src := allIPs[rand.Intn(len(allIPs))]
		switch rand.Intn(3) {
		case 0: // DNS — crosses to mgmt-net via router
			sendIfUp(exp, []flowexp.Record{
				{SrcIP: src, DstIP: ipRouterServers, SrcPort: randPort(), DstPort: 53,
					Protocol: 17, Packets: 1, Bytes: uint32(40 + rand.Intn(60))},
				{SrcIP: ipRouterMgmt, DstIP: ipDNS, SrcPort: randPort(), DstPort: 53,
					Protocol: 17, Packets: 1, Bytes: uint32(40 + rand.Intn(60))},
				{SrcIP: ipDNS, DstIP: ipRouterMgmt, SrcPort: 53, DstPort: randPort(),
					Protocol: 17, Packets: 1, Bytes: uint32(80 + rand.Intn(120))},
			})
		case 1: // NTP — crosses to mgmt-net via router
			sendIfUp(exp, []flowexp.Record{
				{SrcIP: src, DstIP: ipRouterServers, SrcPort: randPort(), DstPort: 123,
					Protocol: 17, Packets: 1, Bytes: 48},
				{SrcIP: ipRouterMgmt, DstIP: ipNTP, SrcPort: randPort(), DstPort: 123,
					Protocol: 17, Packets: 1, Bytes: 48},
				{SrcIP: ipNTP, DstIP: ipRouterMgmt, SrcPort: 123, DstPort: randPort(),
					Protocol: 17, Packets: 1, Bytes: 48},
			})
		case 2: // Syslog — crosses to mgmt-net via router
			sendIfUp(exp, []flowexp.Record{
				{SrcIP: src, DstIP: ipRouterServers, SrcPort: randPort(), DstPort: 514,
					Protocol: 17, Packets: 1, Bytes: uint32(100 + rand.Intn(400))},
				{SrcIP: ipRouterMgmt, DstIP: ipLogSrv, SrcPort: randPort(), DstPort: 514,
					Protocol: 17, Packets: 1, Bytes: uint32(100 + rand.Intn(400))},
			})
		}
		time.Sleep(time.Duration(500+rand.Intn(2000)) * time.Millisecond)
	}
}

// RunICMP simulates periodic ping health checks including cross-segment paths via router.
func RunICMP(exp *flowexp.Exporter) {
	pairs := [][2]net.IP{
		// Same-segment
		{ipWSAlpha, ipServer},
		{ipWSBravo, ipServer},
		{ipWSCharlie, ipSwitchServers},
		// Cross-segment via router
		{ipWSAlpha, ipRouterServers},
		{ipRouterSensors, ipSens},
		{ipRouterMgmt, ipCollector},
		{ipSens, ipRouterSensors},
	}
	for {
		p := pairs[rand.Intn(len(pairs))]
		sendIfUp(exp, []flowexp.Record{
			{SrcIP: p[0], DstIP: p[1], Protocol: 1, Packets: 4, Bytes: 4 * 84},
			{SrcIP: p[1], DstIP: p[0], Protocol: 1, Packets: 4, Bytes: 4 * 84},
		})
		time.Sleep(jitter(25, 15))
	}
}

// RunSensorTraffic simulates the GPS sensor reporting to the server via the router.
func RunSensorTraffic(exp *flowexp.Exporter) {
	for {
		pkts := uint32(3 + rand.Intn(8))
		// Sensor → router (sensors-net hop)
		sendIfUp(exp, []flowexp.Record{{
			SrcIP: ipSens, DstIP: ipRouterSensors,
			SrcPort: randPort(), DstPort: 8080,
			Protocol: 6, TCPFlags: 0x18,
			Packets: pkts, Bytes: pkts * uint32(100+rand.Intn(300)),
		}})
		// Router → server (servers-net hop)
		sendIfUp(exp, []flowexp.Record{{
			SrcIP: ipRouterServers, DstIP: ipServer,
			SrcPort: randPort(), DstPort: 8080,
			Protocol: 6, TCPFlags: 0x18,
			Packets: pkts, Bytes: pkts * uint32(100+rand.Intn(300)),
		}})
		time.Sleep(jitter(60, 120))
	}
}

// RunStatusReport simulates workstation A posting status updates to the server.
func RunStatusReport(serverAddr string, exp *flowexp.Exporter) {
	for {
		body, _ := json.Marshal(map[string]string{
			"unit_id": "NODE-A1", "status": "OPERATIONAL", "location": "ZONE-4",
		})
		resp, err := httpClient.Post(serverAddr+"/api/status", "application/json", bytes.NewReader(body))
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}

		sendIfUp(exp, []flowexp.Record{{
			SrcIP: ipWSAlpha, DstIP: ipServer,
			SrcPort: randPort(), DstPort: 8080,
			Protocol: 6, TCPFlags: 0x18,
			Packets: uint32(4 + rand.Intn(6)), Bytes: uint32(300 + rand.Intn(500)),
		}})

		time.Sleep(jitter(120, 120))
	}
}
