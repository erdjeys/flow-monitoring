#!/bin/sh

# Enable IP forwarding — may be read-only on Docker Desktop (Windows/Mac); ignore error
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || \
  echo "[ROUTER] sysctl ip_forward skipped (read-only FS — Docker Desktop)"

# Accept forwarded packets; ignore if iptables unavailable
iptables -I FORWARD -j ACCEPT 2>/dev/null || \
  echo "[ROUTER] iptables FORWARD skipped"

# MASQUERADE so return traffic routes correctly
iptables -t nat -A POSTROUTING -j MASQUERADE 2>/dev/null || \
  echo "[ROUTER] iptables MASQUERADE skipped"

echo "[ROUTER] IP forwarding active"
echo "[ROUTER] Routing table:"
ip route

exec /router
