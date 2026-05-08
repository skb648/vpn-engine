#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# setup_tun.sh — One-time TUN + iptables setup for the VPN proxy server
#
# This script creates and configures the TUN interface and firewall rules
# that the proxy_server.py needs. Run this once before starting the proxy,
# or let the proxy configure it automatically on startup.
#
# Usage:
#   sudo bash setup_tun.sh          # Setup
#   sudo bash setup_tun.sh --teardown  # Remove rules
#
# Requirements:
#   - Root access
#   - ip, iptables, sysctl commands available
#   - /dev/net/tun available (or will be created)
# ──────────────────────────────────────────────────────────────────────────────

set -euo pipefail

TUN_NAME="tun0"
GATEWAY_IP="10.0.0.1/24"
NETWORK="10.0.0.0/24"
MTU=1500

# Detect external interface
detect_ext_if() {
    local ext_if
    ext_if=$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
    if [ -z "$ext_if" ]; then
        echo "ERROR: Cannot detect default route interface" >&2
        exit 1
    fi
    echo "$ext_if"
}

setup() {
    echo "=== VPN Proxy Server — TUN Setup ==="

    # Create /dev/net/tun if it doesn't exist
    if [ ! -c /dev/net/tun ]; then
        echo "Creating /dev/net/tun..."
        mkdir -p /dev/net
        mknod /dev/net/tun c 10 200
        chmod 666 /dev/net/tun
    fi

    # Detect external interface
    EXT_IF=$(detect_ext_if)
    echo "External interface: $EXT_IF"

    # Create TUN interface (the proxy server does this via ioctl,
    # but we can pre-create it for testing)
    # ip tuntap add dev $TUN_NAME mode tun

    # Configure TUN interface
    echo "Configuring $TUN_NAME with $GATEWAY_IP..."
    ip addr add $GATEWAY_IP dev $TUN_NAME 2>/dev/null || echo "  (address already assigned)"
    ip link set $TUN_NAME up
    ip link set $TUN_NAME mtu $MTU

    # Enable IP forwarding
    echo "Enabling IP forwarding..."
    sysctl -w net.ipv4.ip_forward=1 > /dev/null

    # iptables NAT rules
    echo "Configuring iptables NAT rules..."
    iptables -t nat -A POSTROUTING -s $NETWORK -o $EXT_IF -j MASQUERADE
    iptables -A FORWARD -i $TUN_NAME -o $EXT_IF -j ACCEPT
    iptables -A FORWARD -i $EXT_IF -o $TUN_NAME -m state --state RELATED,ESTABLISHED -j ACCEPT

    echo ""
    echo "=== Setup Complete ==="
    echo "  TUN Interface:  $TUN_NAME ($GATEWAY_IP)"
    echo "  MTU:            $MTU"
    echo "  External:       $EXT_IF"
    echo "  NAT Network:    $NETWORK → $EXT_IF (MASQUERADE)"
    echo ""
    echo "  Now start the proxy:  python3 proxy_server.py"
    echo "  Or with Ngrok:       ngrok tcp 8080 &"
}

teardown() {
    echo "=== VPN Proxy Server — TUN Teardown ==="

    EXT_IF=$(detect_ext_if 2>/dev/null || echo "eth0")

    echo "Removing iptables rules..."
    iptables -t nat -D POSTROUTING -s $NETWORK -o $EXT_IF -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i $TUN_NAME -o $EXT_IF -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i $EXT_IF -o $TUN_NAME -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

    echo "Bringing down $TUN_NAME..."
    ip link set $TUN_NAME down 2>/dev/null || true
    ip addr flush dev $TUN_NAME 2>/dev/null || true

    echo "=== Teardown Complete ==="
}

case "${1:-setup}" in
    --teardown|-t)
        teardown
        ;;
    setup|-s|"")
        setup
        ;;
    *)
        echo "Usage: $0 [--teardown|setup]"
        exit 1
        ;;
esac
