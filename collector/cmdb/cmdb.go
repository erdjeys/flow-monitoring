// Package cmdb provides passive asset discovery and topology tracking backed by Postgres.
// Every device that appears in a flow record is automatically added to the inventory
// without any active scanning — making "shadow IT" devices visible the moment they
// communicate on the network.
package cmdb

import (
	"database/sql"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"

	"github.com/flowmonitor/collector/influx"
)

// ── Array scanners ────────────────────────────────────────────────────────────
// pq returns Postgres integer[] and text[] as raw "{...}" strings.

type portArray []int64

func (a *portArray) Scan(src interface{}) error {
	s, err := srcToString(src)
	if err != nil {
		return fmt.Errorf("portArray: %w", err)
	}
	s = strings.Trim(s, "{}")
	if s == "" {
		return nil
	}
	for _, part := range strings.Split(s, ",") {
		n, err := strconv.ParseInt(strings.TrimSpace(part), 10, 64)
		if err != nil {
			return err
		}
		*a = append(*a, n)
	}
	return nil
}
type stringArray []string

func (a *stringArray) Scan(src interface{}) error {
	s, err := srcToString(src)
	if err != nil {
		return fmt.Errorf("stringArray: %w", err)
	}
	s = strings.Trim(s, "{}")
	if s == "" {
		return nil
	}
	for _, part := range strings.Split(s, ",") {
		*a = append(*a, strings.Trim(strings.TrimSpace(part), `"`))
	}
	return nil
}

func srcToString(src interface{}) (string, error) {
	switch v := src.(type) {
	case nil:
		return "", nil
	case string:
		return v, nil
	case []byte:
		return string(v), nil
	default:
		return "", fmt.Errorf("unsupported type %T", src)
	}
}

// ── CMDB ──────────────────────────────────────────────────────────────────────

// CMDB maintains an asset inventory and logical topology map derived from
// observed flow records — no active scanning required.
type CMDB struct {
	db    *sql.DB
	mu    sync.Mutex
	known map[string]bool // IP → already registered in DB
}

func New(dsn string) (*CMDB, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	var pingErr error
	for i := 0; i < 15; i++ {
		if pingErr = db.Ping(); pingErr == nil {
			break
		}
		log.Printf("cmdb: waiting for postgres (%d/15): %v", i+1, pingErr)
		time.Sleep(2 * time.Second)
	}
	if pingErr != nil {
		db.Close()
		return nil, fmt.Errorf("postgres not ready: %w", pingErr)
	}
	c := &CMDB{db: db, known: make(map[string]bool)}
	if err := c.migrate(); err != nil {
		return nil, err
	}
	return c, c.loadKnown()
}

func (c *CMDB) migrate() error {
	// Base tables (unchanged schema — always safe to run).
	if _, err := c.db.Exec(`
		CREATE TABLE IF NOT EXISTS assets (
			ip         TEXT PRIMARY KEY,
			mac        TEXT    NOT NULL DEFAULT '',
			first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			last_seen  TIMESTAMPTZ NOT NULL,
			ports      INTEGER[] NOT NULL DEFAULT '{}',
			protocols  TEXT[]    NOT NULL DEFAULT '{}'
		);
		CREATE TABLE IF NOT EXISTS topology (
			src_ip    TEXT NOT NULL,
			dst_ip    TEXT NOT NULL,
			packets   BIGINT NOT NULL DEFAULT 0,
			bytes     BIGINT NOT NULL DEFAULT 0,
			last_seen TIMESTAMPTZ NOT NULL,
			PRIMARY KEY (src_ip, dst_ip)
		);
	`); err != nil {
		return err
	}

	// Alerts table — persists anomaly detector events so Grafana can query them.
	if _, err := c.db.Exec(`
		CREATE TABLE IF NOT EXISTS alerts (
			id         BIGSERIAL    PRIMARY KEY,
			time       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
			alert_type TEXT         NOT NULL,
			severity   TEXT         NOT NULL,
			src_ip     TEXT         NOT NULL DEFAULT '',
			dst_ip     TEXT         NOT NULL DEFAULT '',
			detail     TEXT         NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS alerts_time_idx ON alerts (time DESC);
		CREATE INDEX IF NOT EXISTS alerts_type_idx ON alerts (alert_type);
	`); err != nil {
		return err
	}

	// Enrichment columns — added with IF NOT EXISTS so upgrades are idempotent.
	enrichCols := []string{
		`ALTER TABLE assets ADD COLUMN IF NOT EXISTS category       TEXT NOT NULL DEFAULT 'UNKNOWN'`,
		`ALTER TABLE assets ADD COLUMN IF NOT EXISTS stealth_score  INT  NOT NULL DEFAULT 100`,
		`ALTER TABLE assets ADD COLUMN IF NOT EXISTS src_flow_count INT  NOT NULL DEFAULT 0`,
		`ALTER TABLE assets ADD COLUMN IF NOT EXISTS dst_flow_count INT  NOT NULL DEFAULT 0`,
	}
	for _, stmt := range enrichCols {
		if _, err := c.db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (c *CMDB) loadKnown() error {
	rows, err := c.db.Query(`SELECT ip FROM assets`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err == nil {
			c.known[ip] = true
		}
	}
	return rows.Err()
}

// ── Observation ───────────────────────────────────────────────────────────────

// Observe processes one flow record: registers new assets, updates counters,
// recomputes classification + stealth score, and updates the topology map.
func (c *CMDB) Observe(r *influx.FlowRecord) {
	now := time.Now()
	c.observeIP(r.SrcIP, r.SrcMAC, int(r.SrcPort), r.Protocol, "src", now)
	c.observeIP(r.DstIP, r.DstMAC, int(r.DstPort), r.Protocol, "dst", now)
	c.updateTopology(r.SrcIP, r.DstIP, r.Packets, r.Bytes, now)
}

// direction is "src" when ip was the initiating party, "dst" when it was the receiver.
func (c *CMDB) observeIP(ip, mac string, port int, proto, direction string, now time.Time) {
	if ip == "" || ip == "0.0.0.0" {
		return
	}

	c.mu.Lock()
	isNew := !c.known[ip]
	if isNew {
		c.known[ip] = true
	}
	c.mu.Unlock()

	if isNew {
		srcDelta, dstDelta := 0, 0
		if direction == "src" {
			srcDelta = 1
		} else {
			dstDelta = 1
		}
		cat := classify(ip, srcDelta, dstDelta, mac)
		ss := stealthScore(srcDelta, dstDelta, mac)

		log.Printf("[DISCOVERY] new %-12s  ip=%-15s  mac=%-17s  stealth=%d",
			cat, ip, mac, ss)

		_, err := c.db.Exec(`
			INSERT INTO assets
				(ip, mac, first_seen, last_seen, ports, protocols,
				 category, stealth_score, src_flow_count, dst_flow_count)
			VALUES ($1,$2,$3,$3,
				ARRAY[$4::integer], ARRAY[$5::text],
				$6,$7,$8,$9)
			ON CONFLICT (ip) DO NOTHING
		`, ip, mac, now, port, proto, cat, ss, srcDelta, dstDelta)
		if err != nil {
			log.Printf("cmdb insert: %v", err)
		}
		return
	}

	// Existing asset: increment direction counter, backfill MAC, append port/proto,
	// then recompute category and stealth_score entirely in SQL.
	srcInc, dstInc := 0, 0
	if direction == "src" {
		srcInc = 1
	} else {
		dstInc = 1
	}

	_, err := c.db.Exec(`
		UPDATE assets SET
			last_seen       = $2,
			mac             = CASE WHEN mac = '' AND $3 <> '' THEN $3 ELSE mac END,
			ports           = CASE WHEN NOT ($4 = ANY(ports))
			                       THEN array_append(ports, $4::integer)
			                       ELSE ports END,
			protocols       = CASE WHEN NOT ($5 = ANY(protocols))
			                       THEN array_append(protocols, $5::text)
			                       ELSE protocols END,
			src_flow_count  = src_flow_count + $6,
			dst_flow_count  = dst_flow_count + $7,

			-- Recompute stealth score: 100 base, reduced by visibility signals.
			stealth_score = GREATEST(0,
				100
				- LEAST(40, (src_flow_count + dst_flow_count + $6 + $7) / 5)
				- CASE WHEN (src_flow_count + $6) > 0 THEN 20 ELSE 0 END
				- CASE WHEN (CASE WHEN mac = '' AND $3 <> '' THEN $3 ELSE mac END) <> '' THEN 10 ELSE 0 END
			),

			-- Recompute category based on IP pattern + traffic direction ratios.
			category = CASE
				WHEN ip LIKE '%.254'                         THEN 'ROUTER'
				WHEN ip LIKE '10.0.1.2' OR ip LIKE '10.0.2.2' THEN 'SWITCH'
				WHEN ip LIKE '10.0.2.%'                      THEN 'SENSOR'
				WHEN (src_flow_count + $6) = 0
				     AND (dst_flow_count + $7) < 3           THEN 'SHADOW'
				WHEN (dst_flow_count + $7) > (src_flow_count + $6) * 5
				     AND (dst_flow_count + $7) > 10          THEN 'SERVER'
				WHEN (src_flow_count + $6) > 50              THEN 'SCANNER'
				WHEN (src_flow_count + $6) > 5               THEN 'WORKSTATION'
				ELSE category
			END
		WHERE ip = $1
	`, ip, now, mac, port, proto, srcInc, dstInc)
	if err != nil {
		log.Printf("cmdb update: %v", err)
	}
}

func (c *CMDB) updateTopology(srcIP, dstIP string, packets, bytes uint64, now time.Time) {
	if srcIP == "" || dstIP == "" || srcIP == "0.0.0.0" || dstIP == "0.0.0.0" {
		return
	}
	_, err := c.db.Exec(`
		INSERT INTO topology (src_ip, dst_ip, packets, bytes, last_seen)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (src_ip, dst_ip) DO UPDATE SET
			packets   = topology.packets + $3,
			bytes     = topology.bytes   + $4,
			last_seen = $5
	`, srcIP, dstIP, int64(packets), int64(bytes), now)
	if err != nil {
		log.Printf("cmdb topology: %v", err)
	}
}

// ── Classification helpers (used for the initial INSERT) ─────────────────────

// classify returns a category string based on IP pattern and initial direction.
func classify(ip string, srcFlows, dstFlows int, mac string) string {
	if strings.HasSuffix(ip, ".254") {
		return "ROUTER"
	}
	if ip == "10.0.1.2" || ip == "10.0.2.2" {
		return "SWITCH"
	}
	if strings.HasPrefix(ip, "10.0.2.") {
		return "SENSOR"
	}
	if srcFlows == 0 && dstFlows < 3 {
		return "SHADOW"
	}
	if dstFlows > srcFlows*5 && dstFlows > 10 {
		return "SERVER"
	}
	if srcFlows > 5 {
		return "WORKSTATION"
	}
	return "UNKNOWN"
}

// stealthScore computes the initial stealth score (0=fully visible, 100=invisible).
func stealthScore(srcFlows, dstFlows int, mac string) int {
	total := srcFlows + dstFlows
	score := 100
	score -= min100(40, total/5)
	if srcFlows > 0 {
		score -= 20
	}
	if mac != "" {
		score -= 10
	}
	if score < 0 {
		return 0
	}
	return score
}

func min100(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ── Query API ─────────────────────────────────────────────────────────────────

// Asset is one enriched entry from the passive inventory.
type Asset struct {
	IP           string    `json:"ip"`
	MAC          string    `json:"mac"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	Ports        []int     `json:"ports"`
	Protocols    []string  `json:"protocols"`
	Category     string    `json:"category"`
	StealthScore int       `json:"stealth_score"`
	SrcFlowCount int       `json:"src_flow_count"`
	DstFlowCount int       `json:"dst_flow_count"`
}

// TopologyEntry records cumulative traffic between two endpoints.
type TopologyEntry struct {
	SrcIP    string    `json:"src_ip"`
	DstIP    string    `json:"dst_ip"`
	Packets  int64     `json:"packets"`
	Bytes    int64     `json:"bytes"`
	LastSeen time.Time `json:"last_seen"`
}

// Assets returns all known assets ordered by stealth_score descending
// (most "invisible" devices first) then by first_seen.
func (c *CMDB) Assets() ([]Asset, error) {
	rows, err := c.db.Query(`
		SELECT ip, mac, first_seen, last_seen, ports, protocols,
		       category, stealth_score, src_flow_count, dst_flow_count
		FROM assets
		ORDER BY stealth_score DESC, first_seen
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Asset
	for rows.Next() {
		var a Asset
		var ports []int64
		if err := rows.Scan(
			&a.IP, &a.MAC, &a.FirstSeen, &a.LastSeen,
			(*portArray)(&ports), (*stringArray)(&a.Protocols),
			&a.Category, &a.StealthScore, &a.SrcFlowCount, &a.DstFlowCount,
		); err != nil {
			return nil, err
		}
		a.Ports = make([]int, len(ports))
		for i, p := range ports {
			a.Ports[i] = int(p)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ShadowAssets returns only assets with stealth_score ≥ threshold.
func (c *CMDB) ShadowAssets(minScore int) ([]Asset, error) {
	rows, err := c.db.Query(`
		SELECT ip, mac, first_seen, last_seen, ports, protocols,
		       category, stealth_score, src_flow_count, dst_flow_count
		FROM assets
		WHERE stealth_score >= $1
		ORDER BY stealth_score DESC, first_seen
	`, minScore)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Asset
	for rows.Next() {
		var a Asset
		var ports []int64
		if err := rows.Scan(
			&a.IP, &a.MAC, &a.FirstSeen, &a.LastSeen,
			(*portArray)(&ports), (*stringArray)(&a.Protocols),
			&a.Category, &a.StealthScore, &a.SrcFlowCount, &a.DstFlowCount,
		); err != nil {
			return nil, err
		}
		a.Ports = make([]int, len(ports))
		for i, p := range ports {
			a.Ports[i] = int(p)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Topology returns observed src→dst pairs ordered by descending byte count.
func (c *CMDB) Topology() ([]TopologyEntry, error) {
	rows, err := c.db.Query(`
		SELECT src_ip, dst_ip, packets, bytes, last_seen
		FROM topology
		ORDER BY bytes DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []TopologyEntry
	for rows.Next() {
		var e TopologyEntry
		if err := rows.Scan(&e.SrcIP, &e.DstIP, &e.Packets, &e.Bytes, &e.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PersistAlert writes one anomaly alert to the alerts table.
// Fields map directly to anomaly.Alert — passed as plain strings to avoid an
// import cycle between the cmdb and anomaly packages.
func (c *CMDB) PersistAlert(alertType, severity, srcIP, dstIP, detail string) error {
	_, err := c.db.Exec(
		`INSERT INTO alerts (alert_type, severity, src_ip, dst_ip, detail)
		 VALUES ($1, $2, $3, $4, $5)`,
		alertType, severity, srcIP, dstIP, detail,
	)
	return err
}

func (c *CMDB) Close() { c.db.Close() }
