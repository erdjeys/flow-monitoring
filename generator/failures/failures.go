// Package failures provides a shared state manager for network failure simulation.
// Profiles goroutines consult this before sending flows so that a "disconnected"
// device simply stops appearing in the traffic — its CMDB last_seen ages out and
// any "device offline" alert fires naturally.
package failures

import (
	"net"
	"sync"
	"time"
)

// Manager tracks which IPs are currently in a simulated failure state.
type Manager struct {
	mu           sync.RWMutex
	disconnected map[string]time.Time // ip → expiry time
}

// Default is the package-level singleton used by all profile goroutines.
var Default = &Manager{
	disconnected: make(map[string]time.Time),
}

// Disconnect silences all flows involving ip for the given duration.
func (m *Manager) Disconnect(ip net.IP, duration time.Duration) {
	m.mu.Lock()
	m.disconnected[ip.String()] = time.Now().Add(duration)
	m.mu.Unlock()
}

// IsDisconnected returns true if ip is currently in a simulated disconnect state.
func (m *Manager) IsDisconnected(ip net.IP) bool {
	if ip == nil {
		return false
	}
	m.mu.RLock()
	exp, ok := m.disconnected[ip.String()]
	m.mu.RUnlock()
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		m.mu.Lock()
		delete(m.disconnected, ip.String())
		m.mu.Unlock()
		return false
	}
	return true
}

// Active returns a snapshot of currently disconnected IPs and their remaining duration.
func (m *Manager) Active() map[string]time.Duration {
	now := time.Now()
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]time.Duration, len(m.disconnected))
	for ip, exp := range m.disconnected {
		if remaining := exp.Sub(now); remaining > 0 {
			out[ip] = remaining
		}
	}
	return out
}
