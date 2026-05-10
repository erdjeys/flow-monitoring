#!/bin/sh
# Add route to servers-net via the core router so this sensor can reach the server.
ip route add 10.0.1.0/24 via 10.0.2.254 2>/dev/null || true
exec /field-device
