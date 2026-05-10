.PHONY:  build up down  logs logs-follow clean status \
        attack-synflood attack-portscan attack-udpflood attack-lateral \
        attack-disconnect attack-cpu-overload attack-link-degrade attack-clear attack-status \
        ipfix-template-get ipfix-template-minimal ipfix-template-full \
        overflow-test inventory-assets inventory-topology inventory-shadow \
        alerts alerts-scan alerts-lateral \
        aggregate-status aggregate-disable aggregate-narrow \


build:
	docker compose build

up:
	docker compose up -d
	@echo ""
	@echo "  Grafana:        http://localhost:3000  (admin/admin)"
	@echo "  Agent API:      http://localhost:8080"
	@echo "  Attack API:     http://localhost:8081/api/status"
	@echo "  Server:         http://localhost:8010"
	@echo "  GPS Sensor:     http://localhost:9000/status"
	@echo "  Router:         http://localhost:8090/status"
	@echo "  Switch-Servers: http://localhost:8091/status"
	@echo "  Switch-Sensors: http://localhost:8092/status"
	@echo ""

down:
	docker compose down

logs:
	docker compose logs --tail=50

logs-follow:
	docker compose logs -f

clean:
	docker compose down -v --remove-orphans
	docker system prune -f

status:
	@curl -sf http://localhost:8090/health  && echo "  Router:         OK" || echo "  Router:         DOWN"
	@curl -sf http://localhost:8091/health  && echo "  Switch-Servers: OK" || echo "  Switch-Servers: DOWN"
	@curl -sf http://localhost:8092/health  && echo "  Switch-Sensors: OK" || echo "  Switch-Sensors: DOWN"
	@curl -sf http://localhost:8010/health  && echo "  Server:         OK" || echo "  Server:         DOWN"
	@curl -sf http://localhost:9000/healthz && echo "  GPS Sensor:     OK" || echo "  GPS Sensor:     DOWN"
	@curl -sf http://localhost:8081/api/status && echo "  Generator:      OK" || echo "  Generator:      DOWN"
	@curl -sf http://localhost:8080/api/status 2>/dev/null && echo "  Agent:          OK" || echo "  Agent:          DOWN"




# ------------- Attacks & failures ------------------

# DDoS - flood the server with TCP SYN packets for 120 s
attack-synflood:
	curl -s -X POST http://localhost:8081/api/attack \
	  -H 'Content-Type: application/json' \
	  -d '{"type":"synflood","target":"10.0.1.10","duration":120}'

# DDoS - flood with UDP packets for 120 s
attack-udpflood:
	curl -s -X POST http://localhost:8081/api/attack \
	  -H 'Content-Type: application/json' \
	  -d '{"type":"udpflood","target":"10.0.1.10","duration":120}'

# Scan ports 1-1024 on the server
attack-portscan:
	curl -s -X POST http://localhost:8081/api/attack \
	  -H 'Content-Type: application/json' \
	  -d '{"type":"portscan","target":"10.0.1.10"}'

# Malware behaviour - connects to many internal IPs pretending to spread
attack-lateral:
	curl -s -X POST http://localhost:8081/api/attack \
	  -H 'Content-Type: application/json' \
	  -d '{"type":"lateral","target":"10.0.1.10"}'

# Port disconnection - silence all traffic from/to the GPS sensor for 2 min.
attack-disconnect:
	curl -s -X POST http://localhost:8081/api/failure \
	  -H 'Content-Type: application/json' \
	  -d '{"type":"disconnect","target":"10.0.2.30","duration":120}'

# CPU overload - burns one agent CPU core for 60 s.
attack-cpu-overload:
	curl -s -X POST http://localhost:8080/api/failure \
	  -H 'Content-Type: application/json' \
	  -d '{"type":"cpu-overload","duration":60}'

# Link degradation - injects 25 % packet loss + 200 ms latency on the sensor to server path.
attack-link-degrade:
	curl -s -X POST http://localhost:8080/api/problem \
	  -H 'Content-Type: application/json' \
	  -d '{"src_ip":"10.0.2.30","dst_ip":"10.0.1.10","protocol":6,"packet_loss":0.25,"latency_ms":200}'

# Clear all active link-degradation impairments
attack-clear:
	curl -s -X DELETE http://localhost:8080/api/problem

# Show which IPs are currently in a simulated disconnect state
attack-disc-status:
	curl -s http://localhost:8081/api/failure | python3 -m json.tool

# ----------- IPFIX template management ------------------

# Shows what template is currently active
ipfix-template-get:
	curl -s http://localhost:8080/api/ipfix/template | python3 -m json.tool


# Only: source/dest IPs, ports, protocol, packets, bytes - minimal bandwidth
ipfix-template-minimal:
	curl -s -X POST http://localhost:8080/api/ipfix/template \
	  -H 'Content-Type: application/json' \
	  -d '{"fields":["srcIP","dstIP","srcPort","dstPort","proto","packets","bytes"]}'

# Everything: IPs, ports, protocol, QoS (ToS), TCP flags, packet/byte counts, flow timestamps, MAC addresses, GPS signal strength, encryption status, sensor health status, CPU load
ipfix-template-full:
	curl -s -X POST http://localhost:8080/api/ipfix/template \
	  -H 'Content-Type: application/json' \
	  -d '{"fields":["srcIP","dstIP","srcPort","dstPort","proto","tos","tcpFlags","packets","bytes","flowStart","flowEnd","srcMAC","dstMAC","signalStrength","encryptionStatus","sensorStatus","cpuLoad"]}'

# ----------------- Cache-overflow simulation ------------------
overflow-test:
	curl -s -X POST http://localhost:8081/api/test/cache-overflow \
	  -H 'Content-Type: application/json' \
	  -d '{"unique_sources":50000}'

# ------------------ Passive inventory ----------------

# Full list of every device ever seen in a flow, with IP, MAC address, category (ROUTER/SWITCH/SENSOR/SERVER), stealth score, and traffic counts
inventory-assets:
	curl -s http://localhost:8079/api/assets | python3 -m json.tool

# Traffic matrix - every source to destination pair seen, with total bytes and packets
inventory-topology:
	curl -s http://localhost:8079/api/topology | python3 -m json.tool

# Only devices with stealth score ≥ 70 - devices that communicate very rarely and are hard to notice
inventory-shadow:
	curl -s "http://localhost:8079/api/assets?shadow=70" | python3 -m json.tool

# ----------------- Anomaly alerts ----------------

# All recent alerts
alerts:
	curl -s http://localhost:8079/api/alerts | python3 -m json.tool

alerts-scan:
	curl -s "http://localhost:8079/api/alerts?type=PORT_SCAN" | python3 -m json.tool

alerts-lateral:
	curl -s "http://localhost:8079/api/alerts?type=LATERAL_MOVEMENT" | python3 -m json.tool

# ----------------- Flow aggregation -------------------

# Shows current aggregation settings and compression stats
aggregate-status:
	curl -s http://localhost:8080/api/aggregate | python3 -m json.tool

# Turns aggregation off 
aggregate-disable:
	curl -s -X POST http://localhost:8080/api/aggregate \
	  -H 'Content-Type: application/json' \
	  -d '{"enabled":false,"level":"none","max_records":0}'

# Enables host-pair aggregation, max 50 records
aggregate-narrow:
	curl -s -X POST http://localhost:8080/api/aggregate \
	  -H 'Content-Type: application/json' \
	  -d '{"enabled":true,"level":"host_pair","max_records":50}'

