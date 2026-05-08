#!/usr/bin/env python3
"""
VPN Proxy Server — Production-grade, asyncio-based, TUN-backed NAT gateway

Architecture:
  ┌──────────────┐     TCP (Ngrok)     ┌─────────────────────────┐
  │ Android VPN  │ ◄──────────────────► │     Proxy Server        │
  │   Client     │   framed IP packets  │                         │
  └──────────────┘                      │  ┌─── Client Session ──┐│
                                        │  │ virtual_ip=10.0.0.2 ││
                                        │  │ reader / writer     ││
                                        │  └─────────────────────┘│
                                        │                         │
                                        │  ┌─── Client Session ──┐│
                                        │  │ virtual_ip=10.0.0.3 ││
                                        │  │ reader / writer     ││
                                        │  └─────────────────────┘│
                                        │                         │
                                        │  ┌─── TUN Device ──────┐│
                                        │  │ tun0 (10.0.0.1/24)  ││
                                        │  │    ↕                 ││
                                        │  │ iptables NAT         ││
                                        │  │    ↕                 ││
                                        │  │ Internet (eth0/wlan0)││
                                        │  └─────────────────────┘│
                                        └─────────────────────────┘

Packet flow (Client → Internet):
  1. Client sends framed IP packet (src=10.0.0.2, dst=93.184.216.34)
  2. Proxy rewrites src to client's assigned virtual IP (if multi-client)
  3. Proxy writes raw IP packet to TUN interface
  4. Kernel routes packet, iptables MASQUERADE NATs source to proxy's public IP
  5. Packet reaches the internet

Packet flow (Internet → Client):
  1. Response arrives at proxy's external interface
  2. iptables conntrack un-NATs destination back to virtual IP (e.g., 10.0.0.2)
  3. Kernel routes to TUN interface (10.0.0.1/24 network)
  4. Proxy reads raw IP packet from TUN
  5. Proxy looks up dst_ip in client session table → finds Client 1
  6. Proxy rewrites dst to client's expected IP (10.0.0.2)
  7. Proxy frames packet and sends over TCP to Client 1

Requirements:
  - Python 3.8+
  - Linux with TUN support (/dev/net/tun)
  - Root access (for TUN + iptables)
  - On Termux: run with `tsu` (Termux su)

Usage:
  # Direct:
  sudo python3 proxy_server.py --listen 0.0.0.0 --port 8080

  # Via Ngrok (Ngrok forwards to localhost:8080):
  ngrok tcp 8080 &
  sudo python3 proxy_server.py --listen 127.0.0.1 --port 8080

Wire protocol (same as C++ client):
  ┌──────────────┬──────────────────────────────┐
  │ uint32_t BE  │       Raw IP Packet           │
  │ length=N     │       (N bytes)               │
  └──────────────┴──────────────────────────────┘
"""

import asyncio
import argparse
import fcntl
import ipaddress
import logging
import os
import signal
import socket
import struct
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional, Set

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

TUN_DEVICE = "/dev/net/tun"
TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

# Virtual IP network for client sessions
VIRTUAL_NETWORK = ipaddress.IPv4Network("10.0.0.0/24")
VIRTUAL_GATEWAY = "10.0.0.1"
TUN_INTERFACE = "tun0"
TUN_MTU = 1500

# Maximum frame size (4-byte header + MTU packet)
MAX_FRAME_SIZE = 4 + TUN_MTU + 64

# Client connection limits
MAX_CLIENTS = 250  # 10.0.0.2 through 10.0.0.251

# Logging
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
logger = logging.getLogger("vpn-proxy")


# ──────────────────────────────────────────────────────────────────────────────
# IP Packet Helpers
# ──────────────────────────────────────────────────────────────────────────────

def extract_dst_ip(packet: bytes) -> Optional[str]:
    """Extract destination IP from an IPv4 or IPv6 packet.
    Returns None if the packet is too short or not a valid IP packet."""
    if len(packet) < 1:
        return None

    version = (packet[0] >> 4) & 0x0F

    if version == 4 and len(packet) >= 20:
        # IPv4: destination IP at offset 16 (4 bytes)
        return socket.inet_ntop(socket.AF_INET, packet[16:20])
    elif version == 6 and len(packet) >= 40:
        # IPv6: destination IP at offset 24 (16 bytes)
        return socket.inet_ntop(socket.AF_INET6, packet[24:40])

    return None


def extract_src_ip(packet: bytes) -> Optional[str]:
    """Extract source IP from an IPv4 or IPv6 packet."""
    if len(packet) < 1:
        return None

    version = (packet[0] >> 4) & 0x0F

    if version == 4 and len(packet) >= 20:
        return socket.inet_ntop(socket.AF_INET, packet[12:16])
    elif version == 6 and len(packet) >= 40:
        return socket.inet_ntop(socket.AF_INET6, packet[8:24])

    return None


def rewrite_ipv4_src(packet: bytes, new_src: str) -> bytes:
    """Rewrite the source IP of an IPv4 packet and recalculate checksums.

    When the source IP changes, we must update:
    1. IP header checksum (incremental update)
    2. TCP/UDP checksum (incremental update via pseudo-header change)

    The incremental checksum update (RFC 1624) is O(1) — no need to
    recompute the entire checksum from scratch.
    """
    if len(packet) < 20:
        return packet

    version = (packet[0] >> 4) & 0x0F
    if version != 4:
        return packet  # Only rewrite IPv4 for now

    pkt = bytearray(packet)
    old_src = pkt[12:16]
    new_src_bytes = socket.inet_pton(socket.AF_INET, new_src)

    # ── Update IP header checksum (incremental) ──────────────────────
    # The checksum is at offset 10-11. We update it for the changed
    # source address words (2 x 16-bit words at offset 12-15).
    old_checksum = struct.unpack("!H", pkt[10:12])[0]
    new_checksum = _incremental_checksum_update_32(
        old_checksum, old_src, new_src_bytes
    )
    pkt[10:12] = struct.pack("!H", new_checksum)

    # ── Update transport checksum (incremental) ──────────────────────
    # TCP/UDP checksums include a pseudo-header with source IP.
    # We update them incrementally for the source IP change.
    ihl = (pkt[0] & 0x0F) * 4
    protocol = pkt[9]
    transport_offset = ihl

    if transport_offset + 2 <= len(pkt):
        transport_checksum = struct.unpack("!H", pkt[transport_offset+2:transport_offset+4])[0]
        if transport_checksum != 0:  # 0 means "no checksum" (UDP only)
            new_transport_checksum = _incremental_checksum_update_32(
                transport_checksum, old_src, new_src_bytes
            )
            pkt[transport_offset+2:transport_offset+4] = struct.pack("!H", new_transport_checksum)

    # ── Write new source IP ──────────────────────────────────────────
    pkt[12:16] = new_src_bytes

    return bytes(pkt)


def rewrite_ipv4_dst(packet: bytes, new_dst: str) -> bytes:
    """Rewrite the destination IP of an IPv4 packet and recalculate checksums."""
    if len(packet) < 20:
        return packet

    version = (packet[0] >> 4) & 0x0F
    if version != 4:
        return packet

    pkt = bytearray(packet)
    old_dst = pkt[16:20]
    new_dst_bytes = socket.inet_pton(socket.AF_INET, new_dst)

    # Update IP header checksum
    old_checksum = struct.unpack("!H", pkt[10:12])[0]
    new_checksum = _incremental_checksum_update_32(old_checksum, old_dst, new_dst_bytes)
    pkt[10:12] = struct.pack("!H", new_checksum)

    # Update transport checksum
    ihl = (pkt[0] & 0x0F) * 4
    protocol = pkt[9]
    transport_offset = ihl

    if transport_offset + 4 <= len(pkt):
        transport_checksum = struct.unpack("!H", pkt[transport_offset+2:transport_offset+4])[0]
        if transport_checksum != 0:
            new_transport_checksum = _incremental_checksum_update_32(
                transport_checksum, old_dst, new_dst_bytes
            )
            pkt[transport_offset+2:transport_offset+4] = struct.pack("!H", new_transport_checksum)

    # Write new destination IP
    pkt[16:20] = new_dst_bytes

    return bytes(pkt)


def _incremental_checksum_update_32(old_checksum: int, old_val_4: bytes, new_val_4: bytes) -> int:
    """Incrementally update a checksum when a 32-bit value changes (RFC 1624).

    HC' = HC - ~m0 - m1 + ~m1' + m0'
    Simplified: HC' = ~(~HC + ~old + new)

    For a 32-bit value change, we process it as two 16-bit words.
    """
    # Extract two 16-bit words from each 32-bit value
    old_hi = struct.unpack("!H", old_val_4[0:2])[0]
    old_lo = struct.unpack("!H", old_val_4[2:4])[0]
    new_hi = struct.unpack("!H", new_val_4[0:2])[0]
    new_lo = struct.unpack("!H", new_val_4[2:4])[0]

    # RFC 1624 incremental update
    # ~HC + ~old + new (in ones-complement arithmetic)
    sum_val = (~old_checksum & 0xFFFF) + (~old_hi & 0xFFFF) + new_hi
    sum_val += (~old_lo & 0xFFFF) + new_lo

    # Fold carries
    while sum_val > 0xFFFF:
        sum_val = (sum_val & 0xFFFF) + (sum_val >> 16)

    return ~sum_val & 0xFFFF


def is_valid_ip_packet(data: bytes) -> bool:
    """Validate that data looks like a valid IP packet."""
    if len(data) < 1:
        return False

    version = (data[0] >> 4) & 0x0F
    if version == 4:
        if len(data) < 20:
            return False
        ihl = (data[0] & 0x0F)
        if ihl < 5:
            return False
        total_length = struct.unpack("!H", data[2:4])[0]
        if total_length < ihl * 4 or total_length > len(data):
            return False
        return True
    elif version == 6:
        return len(data) >= 40
    return False


# ──────────────────────────────────────────────────────────────────────────────
# TUN Device Manager
# ──────────────────────────────────────────────────────────────────────────────

class TunDevice:
    """Manages a Linux TUN network interface.

    The TUN device allows the proxy to write raw IP packets into the
    kernel's network stack (as if they arrived on a network interface)
    and read IP packets that the kernel routes out through this interface.

    Lifecycle:
    1. Open /dev/net/tun and create tun0 via ioctl
    2. Configure IP address (10.0.0.1/24) and bring up via `ip` commands
    3. Enable IP forwarding via sysctl
    4. Set up iptables MASQUERADE NAT for outgoing traffic
    5. On shutdown: remove iptables rules, bring down interface, close FD

    Thread safety: This class is used from the asyncio event loop thread
    only. The TUN FD is registered with the event loop for non-blocking reads.
    """

    def __init__(self, name: str = TUN_INTERFACE, mtu: int = TUN_MTU):
        self.name = name
        self.mtu = mtu
        self.fd: Optional[int] = None
        self._external_interface: Optional[str] = None

    def open(self) -> int:
        """Open the TUN device and return the file descriptor.
        Raises RuntimeError if the device cannot be created."""
        if not os.path.exists(TUN_DEVICE):
            # Create /dev/net/tun if it doesn't exist (needs root)
            os.makedirs("/dev/net", exist_ok=True)
            subprocess.run(["mknod", TUN_DEVICE, "c", "10", "200"],
                           check=True, capture_output=True)

        self.fd = os.open(TUN_DEVICE, os.O_RDWR | os.O_NONBLOCK)

        # Configure the TUN interface via ioctl
        ifr = struct.pack("16sH", self.name.encode(), IFF_TUN | IFF_NO_PI)
        try:
            fcntl.ioctl(self.fd, TUNSETIFF, ifr)
        except OSError as e:
            os.close(self.fd)
            self.fd = None
            raise RuntimeError(f"ioctl(TUNSETIFF) failed: {e}")

        logger.info(f"TUN device '{self.name}' opened (fd={self.fd})")
        return self.fd

    def configure(self) -> None:
        """Configure the TUN interface with IP, routes, and NAT rules.
        Requires root. Must be called after open()."""
        if self.fd is None:
            raise RuntimeError("TUN device not opened")

        # Detect the default external interface (eth0, wlan0, rmnet0, etc.)
        self._external_interface = self._detect_external_interface()
        if not self._external_interface:
            raise RuntimeError("Cannot detect external network interface")

        logger.info(f"External interface: {self._external_interface}")

        # Assign IP address to TUN interface
        self._run_command(
            ["ip", "addr", "add", f"{VIRTUAL_GATEWAY}/24", "dev", self.name],
            f"Add IP {VIRTUAL_GATEWAY}/24 to {self.name}"
        )

        # Bring up the interface
        self._run_command(
            ["ip", "link", "set", self.name, "up"],
            f"Bring up {self.name}"
        )

        # Set MTU
        self._run_command(
            ["ip", "link", "set", self.name, "mtu", str(self.mtu)],
            f"Set MTU {self.mtu} on {self.name}"
        )

        # Enable IP forwarding
        self._run_command(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            "Enable IPv4 forwarding"
        )

        # Add iptables NAT rule (MASQUERADE)
        # This translates source IPs from 10.0.0.0/24 to the external interface IP
        self._run_command(
            ["iptables", "-t", "nat", "-A", "POSTROUTING",
             "-s", str(VIRTUAL_NETWORK), "-o", self._external_interface,
             "-j", "MASQUERADE"],
            f"Add MASQUERADE rule for {VIRTUAL_NETWORK} via {self._external_interface}"
        )

        # Allow forwarding from TUN to external
        self._run_command(
            ["iptables", "-A", "FORWARD",
             "-i", self.name, "-o", self._external_interface,
             "-j", "ACCEPT"],
            "Allow forwarding: tun → external"
        )

        # Allow forwarding from external to TUN (for return traffic)
        self._run_command(
            ["iptables", "-A", "FORWARD",
             "-i", self._external_interface, "-o", self.name,
             "-m", "state", "--state", "RELATED,ESTABLISHED",
             "-j", "ACCEPT"],
            "Allow forwarding: external → tun (established)"
        )

        logger.info("TUN interface configured successfully")

    def cleanup(self) -> None:
        """Remove iptables rules and bring down the TUN interface."""
        if self._external_interface:
            # Remove iptables rules (best-effort — don't fail on errors)
            self._run_command(
                ["iptables", "-t", "nat", "-D", "POSTROUTING",
                 "-s", str(VIRTUAL_NETWORK), "-o", self._external_interface,
                 "-j", "MASQUERADE"],
                "Remove MASQUERADE rule",
                check=False
            )
            self._run_command(
                ["iptables", "-D", "FORWARD",
                 "-i", self.name, "-o", self._external_interface,
                 "-j", "ACCEPT"],
                "Remove forward rule (tun→ext)",
                check=False
            )
            self._run_command(
                ["iptables", "-D", "FORWARD",
                 "-i", self._external_interface, "-o", self.name,
                 "-m", "state", "--state", "RELATED,ESTABLISHED",
                 "-j", "ACCEPT"],
                "Remove forward rule (ext→tun)",
                check=False
            )

        if self.name:
            self._run_command(
                ["ip", "link", "set", self.name, "down"],
                f"Bring down {self.name}",
                check=False
            )
            self._run_command(
                ["ip", "addr", "flush", "dev", self.name],
                f"Flush addresses on {self.name}",
                check=False
            )

        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

        logger.info("TUN device cleaned up")

    def read_packet(self) -> Optional[bytes]:
        """Read one IP packet from the TUN device (non-blocking).
        Returns None if no packet is available (EAGAIN)."""
        if self.fd is None:
            return None
        try:
            return os.read(self.fd, self.mtu + 64)
        except BlockingIOError:
            return None
        except OSError as e:
            if e.errno == 11:  # EAGAIN
                return None
            logger.error(f"TUN read error: {e}")
            return None

    def write_packet(self, packet: bytes) -> bool:
        """Write one IP packet to the TUN device.
        Returns True on success, False on failure."""
        if self.fd is None:
            return False
        try:
            os.write(self.fd, packet)
            return True
        except BlockingIOError:
            # TUN write buffer full — drop packet (rare on modern kernels)
            logger.warning("TUN write buffer full — dropping packet")
            return False
        except OSError as e:
            logger.error(f"TUN write error: {e}")
            return False

    @staticmethod
    def _detect_external_interface() -> Optional[str]:
        """Detect the default route's outgoing interface."""
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, check=True
            )
            # Output: "default via 192.168.1.1 dev wlan0"
            for line in result.stdout.strip().split("\n"):
                if "dev" in line:
                    parts = line.split()
                    dev_idx = parts.index("dev")
                    if dev_idx + 1 < len(parts):
                        return parts[dev_idx + 1]
        except Exception as e:
            logger.error(f"Failed to detect external interface: {e}")
        return None

    @staticmethod
    def _run_command(cmd: list, description: str, check: bool = True) -> None:
        """Run a subprocess command with logging."""
        logger.debug(f"Running: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=check)
            if result.returncode != 0 and not check:
                logger.warning(f"{description} failed (non-fatal): {result.stderr.strip()}")
        except subprocess.CalledProcessError as e:
            logger.error(f"{description} failed: {e.stderr.strip()}")
            raise
        except FileNotFoundError as e:
            logger.error(f"{description}: command not found: {cmd[0]}")
            raise


# ──────────────────────────────────────────────────────────────────────────────
# Virtual IP Pool
# ──────────────────────────────────────────────────────────────────────────────

class VirtualIPPool:
    """Manages a pool of virtual IP addresses for client sessions.

    Each client is assigned a unique virtual IP from 10.0.0.0/24.
    This IP is used by the proxy to route return traffic back to the
    correct client via iptables conntrack.

    IP allocation:
    - 10.0.0.1   → Gateway (TUN interface address, never assigned)
    - 10.0.0.2   → First client
    - 10.0.0.3   → Second client
    - ...
    - 10.0.0.251 → Last client (MAX_CLIENTS = 250)
    """

    def __init__(self, network: str = str(VIRTUAL_NETWORK), max_clients: int = MAX_CLIENTS):
        self._network = ipaddress.IPv4Network(network)
        self._assigned: Dict[str, int] = {}  # ip_str → client_id
        self._reverse: Dict[int, str] = {}   # client_id → ip_str
        self._next_client_id = 0
        self._max_clients = max_clients

    def allocate(self, client_id: int) -> Optional[str]:
        """Allocate a virtual IP for a client. Returns the IP string or None if exhausted."""
        if len(self._assigned) >= self._max_clients:
            return None

        # Skip .0 (network) and .1 (gateway) and .255 (broadcast)
        for host_int in range(2, 255):
            ip_str = str(self._network.network_address + host_int)
            if ip_str not in self._assigned:
                self._assigned[ip_str] = client_id
                self._reverse[client_id] = ip_str
                return ip_str

        return None  # All IPs exhausted

    def release(self, client_id: int) -> None:
        """Release a virtual IP back to the pool."""
        ip_str = self._reverse.pop(client_id, None)
        if ip_str:
            self._assigned.pop(ip_str, None)

    def get_ip(self, client_id: int) -> Optional[str]:
        """Get the virtual IP assigned to a client."""
        return self._reverse.get(client_id)

    def get_client_id(self, ip_str: str) -> Optional[int]:
        """Look up which client owns a virtual IP."""
        return self._assigned.get(ip_str)


# ──────────────────────────────────────────────────────────────────────────────
# Client Session
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ClientSession:
    """State for a single connected VPN client.

    Each client gets:
    - A unique virtual IP (10.0.0.x) for TUN routing
    - A reader coroutine that reads framed packets from the TCP socket
    - A write buffer for sending framed packets back to the client
    """
    client_id: int
    virtual_ip: str
    expected_client_ip: str   # The IP the client's TUN is configured with
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    connected_at: float = field(default_factory=time.time)

    # Statistics
    packets_received: int = 0  # From client
    packets_sent: int = 0      # To client
    bytes_received: int = 0
    bytes_sent: int = 0

    # Write buffer and backpressure
    _write_buffer: list = field(default_factory=list)
    _write_buffer_size: int = 0
    MAX_WRITE_BUFFER = 512 * 1024  # 512 KB

    @property
    def remote_addr(self) -> str:
        try:
            return f"{self.writer.get_extra_info('peername')}"
        except Exception:
            return "unknown"

    def queue_packet(self, framed_packet: bytes) -> bool:
        """Queue a framed packet for sending to the client.
        Returns False if the buffer is full (packet dropped)."""
        if self._write_buffer_size >= self.MAX_WRITE_BUFFER:
            return False  # Backpressure — drop the packet
        self._write_buffer.append(framed_packet)
        self._write_buffer_size += len(framed_packet)
        return True

    def drain_buffer(self) -> list:
        """Return and clear the write buffer."""
        packets = self._write_buffer
        self._write_buffer = []
        self._write_buffer_size = 0
        return packets


# ──────────────────────────────────────────────────────────────────────────────
# Proxy Server
# ──────────────────────────────────────────────────────────────────────────────

class ProxyServer:
    """Main VPN proxy server.

    Accepts TCP connections from VPN clients, reads framed IP packets,
    writes them to a TUN interface for kernel routing/NAT, reads response
    packets from TUN, and routes them back to the correct client.
    """

    def __init__(self, listen_host: str, listen_port: int,
                 tun_name: str = TUN_INTERFACE):
        self.listen_host = listen_host
        self.listen_port = listen_port

        self.tun = TunDevice(name=tun_name)
        self.ip_pool = VirtualIPPool()

        # Client sessions: client_id → ClientSession
        self.clients: Dict[int, ClientSession] = {}
        # Virtual IP → client_id (for TUN→client routing)
        self.ip_to_client: Dict[str, int] = {}

        self._next_client_id = 1
        self._running = False
        self._server: Optional[asyncio.AbstractServer] = None
        self._tun_read_task: Optional[asyncio.Task] = None
        self._stats_task: Optional[asyncio.Task] = None
        self._drain_task: Optional[asyncio.Task] = None

        # The IP address the client's TUN is configured with.
        # By convention, Android VpnService sets this to 10.0.0.2.
        self.client_tunnel_ip = "10.0.0.2"

    async def start(self) -> None:
        """Start the proxy server."""
        logger.info("Starting VPN Proxy Server...")

        # ── Open and configure TUN ─────────────────────────────────────
        try:
            self.tun.open()
            self.tun.configure()
        except Exception as e:
            logger.error(f"Failed to configure TUN device: {e}")
            logger.error("Make sure you are running as root (use 'tsu' on Termux)")
            raise

        # ── Start TCP server ───────────────────────────────────────────
        self._running = True
        self._server = await asyncio.start_server(
            self._handle_client,
            self.listen_host,
            self.listen_port
        )

        addr = self._server.sockets[0].getsockname()
        logger.info(f"Listening on {addr[0]}:{addr[1]}")
        logger.info(f"Ngrok: ngrok tcp {addr[1]}")

        # ── Start background tasks ─────────────────────────────────────
        self._tun_read_task = asyncio.create_task(self._tun_read_loop())
        self._stats_task = asyncio.create_task(self._stats_loop())
        self._drain_task = asyncio.create_task(self._client_drain_loop())

        # ── Serve ──────────────────────────────────────────────────────
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        """Gracefully stop the proxy server."""
        logger.info("Stopping VPN Proxy Server...")
        self._running = False

        # Cancel background tasks
        for task in [self._tun_read_task, self._stats_task, self._drain_task]:
            if task and not task.done():
                task.cancel()

        # Close all client connections
        for client in list(self.clients.values()):
            try:
                client.writer.close()
                await client.writer.wait_closed()
            except Exception:
                pass

        self.clients.clear()
        self.ip_to_client.clear()

        # Cleanup TUN
        self.tun.cleanup()

        # Close server
        if self._server:
            self._server.close()
            await self._server.wait_closed()

        logger.info("VPN Proxy Server stopped")

    # ──────────────────────────────────────────────────────────────────
    # Client connection handler
    # ──────────────────────────────────────────────────────────────────

    async def _handle_client(self, reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter) -> None:
        """Handle a new client connection.

        This coroutine runs for the lifetime of a single client connection.
        It reads framed IP packets from the client and writes them to TUN.
        """
        client_id = self._next_client_id
        self._next_client_id += 1

        peer = writer.get_extra_info("peername")
        logger.info(f"Client {client_id} connected from {peer}")

        # ── Allocate virtual IP ────────────────────────────────────────
        virtual_ip = self.ip_pool.allocate(client_id)
        if virtual_ip is None:
            logger.error(f"No virtual IPs available — rejecting client {client_id}")
            writer.close()
            await writer.wait_closed()
            return

        # ── Create session ─────────────────────────────────────────────
        session = ClientSession(
            client_id=client_id,
            virtual_ip=virtual_ip,
            expected_client_ip=self.client_tunnel_ip,
            reader=reader,
            writer=writer,
        )
        self.clients[client_id] = session
        self.ip_to_client[virtual_ip] = client_id

        logger.info(f"Client {client_id} assigned virtual IP {virtual_ip}")

        try:
            # ── Read loop: client → TUN ───────────────────────────────
            while self._running:
                try:
                    # Read 4-byte length prefix
                    length_data = await reader.readexactly(4)
                    packet_length = struct.unpack("!I", length_data)[0]

                    # Sanity check
                    if packet_length == 0 or packet_length > TUN_MTU + 64:
                        logger.warning(
                            f"Client {client_id}: invalid frame length {packet_length} — closing"
                        )
                        break

                    # Read the raw IP packet
                    packet = await reader.readexactly(packet_length)

                except asyncio.IncompleteReadError:
                    logger.info(f"Client {client_id}: connection closed (incomplete read)")
                    break
                except asyncio.CancelledError:
                    break
                except ConnectionResetError:
                    logger.info(f"Client {client_id}: connection reset by peer")
                    break
                except OSError as e:
                    logger.warning(f"Client {client_id}: read error: {e}")
                    break

                # ── Validate the packet ────────────────────────────────
                if not is_valid_ip_packet(packet):
                    logger.debug(f"Client {client_id}: invalid IP packet ({len(packet)} bytes) — dropping")
                    continue

                # ── NAT: Rewrite source IP ─────────────────────────────
                # The client sends packets with src=10.0.0.2 (its TUN IP).
                # We rewrite it to the client's assigned virtual_ip so that
                # return traffic can be routed back to this specific client.
                #
                # Before: src=10.0.0.2, dst=93.184.216.34
                # After:  src=10.0.0.N, dst=93.184.216.34  (N = client's virtual IP)
                src_ip = extract_src_ip(packet)
                if src_ip and src_ip != virtual_ip:
                    if src_ip == session.expected_client_ip:
                        # Rewrite client's expected IP to their assigned virtual IP
                        packet = rewrite_ipv4_src(packet, virtual_ip)
                    # else: packet already has the correct src (or is IPv6 — skip)

                # ── Write to TUN ───────────────────────────────────────
                if not self.tun.write_packet(packet):
                    logger.debug(f"Client {client_id}: TUN write failed — dropping packet")

                session.packets_received += 1
                session.bytes_received += len(packet)

        except Exception as e:
            logger.error(f"Client {client_id}: unexpected error: {e}")
        finally:
            # ── Cleanup ────────────────────────────────────────────────
            logger.info(
                f"Client {client_id} disconnected: "
                f"pkts_in={session.packets_received} pkts_out={session.packets_sent} "
                f"bytes_in={session.bytes_received} bytes_out={session.bytes_sent}"
            )
            self.clients.pop(client_id, None)
            self.ip_to_client.pop(virtual_ip, None)
            self.ip_pool.release(client_id)

            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ──────────────────────────────────────────────────────────────────
    # TUN → Client routing loop
    # ──────────────────────────────────────────────────────────────────

    async def _tun_read_loop(self) -> None:
        """Read IP packets from the TUN interface and route them to clients.

        This loop runs as a background task. It uses asyncio's event loop
        to watch the TUN FD for readability. When a packet is available,
        it reads it, determines the destination client based on the dst IP,
        rewrites the destination IP back to the client's expected IP, frames
        the packet, and queues it for sending.
        """
        loop = asyncio.get_event_loop()
        tun_fd = self.tun.fd

        if tun_fd is None:
            logger.error("TUN FD is None — cannot start read loop")
            return

        # Create a Future that gets set whenever the TUN FD is readable
        tun_read_event = asyncio.Event()

        def _tun_readable():
            tun_read_event.set()

        loop.add_reader(tun_fd, _tun_readable)

        logger.info("TUN read loop started")

        try:
            while self._running:
                # Wait for TUN to become readable
                try:
                    await asyncio.wait_for(tun_read_event.wait(), timeout=1.0)
                    tun_read_event.clear()
                except asyncio.TimeoutError:
                    continue

                # Read all available packets (the kernel may buffer multiple)
                while True:
                    packet = self.tun.read_packet()
                    if packet is None:
                        break  # No more packets

                    # ── Route packet to client ─────────────────────────
                    dst_ip = extract_dst_ip(packet)
                    if dst_ip is None:
                        continue

                    # Look up which client owns this virtual IP
                    client_id = self.ip_to_client.get(dst_ip) if dst_ip in self.ip_to_client else self.ip_pool.get_client_id(dst_ip)
                    if client_id is None:
                        # No client for this IP — might be broadcast or
                        # a packet for the gateway itself. Drop silently.
                        continue

                    session = self.clients.get(client_id)
                    if session is None:
                        continue

                    # ── NAT: Rewrite destination IP ────────────────────
                    # The packet's dst is the client's virtual IP (10.0.0.N).
                    # We rewrite it to the client's expected TUN IP (10.0.0.2).
                    #
                    # Before: src=93.184.216.34, dst=10.0.0.N
                    # After:  src=93.184.216.34, dst=10.0.0.2
                    if dst_ip != session.expected_client_ip:
                        packet = rewrite_ipv4_dst(packet, session.expected_client_ip)

                    # ── Frame and queue ─────────────────────────────────
                    framed = struct.pack("!I", len(packet)) + packet
                    if not session.queue_packet(framed):
                        logger.debug(
                            f"Client {client_id}: write buffer full — dropping response packet"
                        )

                    session.packets_sent += 1
                    session.bytes_sent += len(packet)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"TUN read loop error: {e}")
        finally:
            loop.remove_reader(tun_fd)
            logger.info("TUN read loop stopped")

    # ──────────────────────────────────────────────────────────────────
    # Client drain loop — sends queued packets to clients
    # ──────────────────────────────────────────────────────────────────

    async def _client_drain_loop(self) -> None:
        """Periodically drain queued packets from client write buffers.

        Instead of writing to clients from the TUN read loop (which could
        block if a client's TCP buffer is full), we queue packets and
        drain them in this separate coroutine. This ensures the TUN read
        loop never blocks on a slow client.
        """
        try:
            while self._running:
                for client_id, session in list(self.clients.items()):
                    packets = session.drain_buffer()
                    if not packets:
                        continue

                    try:
                        for framed in packets:
                            session.writer.write(framed)
                        await session.writer.drain()
                    except ConnectionResetError:
                        logger.debug(f"Client {client_id}: connection reset while writing")
                    except OSError as e:
                        logger.debug(f"Client {client_id}: write error: {e}")
                    except Exception:
                        pass

                await asyncio.sleep(0.005)  # 5ms — balances latency vs CPU

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Client drain loop error: {e}")

    # ──────────────────────────────────────────────────────────────────
    # Statistics logging
    # ──────────────────────────────────────────────────────────────────

    async def _stats_loop(self) -> None:
        """Log server statistics every 30 seconds."""
        try:
            while self._running:
                await asyncio.sleep(30)

                num_clients = len(self.clients)
                total_in = sum(s.packets_received for s in self.clients.values())
                total_out = sum(s.packets_sent for s in self.clients.values())
                total_bytes_in = sum(s.bytes_received for s in self.clients.values())
                total_bytes_out = sum(s.bytes_sent for s in self.clients.values())

                logger.info(
                    f"Stats: clients={num_clients} "
                    f"pkts_in={total_in} pkts_out={total_out} "
                    f"bytes_in={total_bytes_in} bytes_out={total_bytes_out} "
                    f"pool_free={MAX_CLIENTS - len(self.ip_pool._assigned)}"
                )

                for cid, session in self.clients.items():
                    buf_kb = session._write_buffer_size / 1024
                    logger.debug(
                        f"  Client {cid} ({session.virtual_ip}): "
                        f"in={session.packets_received} out={session.packets_sent} "
                        f"buf={buf_kb:.1f}KB"
                    )

        except asyncio.CancelledError:
            pass


# ──────────────────────────────────────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────────────────────────────────────

def check_root() -> bool:
    """Check if the script is running as root."""
    return os.geteuid() == 0


async def main_async(args):
    """Async entry point."""
    server = ProxyServer(
        listen_host=args.listen,
        listen_port=args.port,
    )

    # Handle signals for graceful shutdown
    loop = asyncio.get_event_loop()

    def signal_handler():
        logger.info("Received shutdown signal")
        asyncio.create_task(server.stop())

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, signal_handler)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass

    try:
        await server.start()
    except KeyboardInterrupt:
        pass
    finally:
        await server.stop()


def main():
    parser = argparse.ArgumentParser(
        description="VPN Proxy Server — TUN-backed NAT gateway for Android VPN clients"
    )
    parser.add_argument(
        "--listen", default="0.0.0.0",
        help="Listen address (default: 0.0.0.0; use 127.0.0.1 for Ngrok)"
    )
    parser.add_argument(
        "--port", type=int, default=8080,
        help="Listen port (default: 8080)"
    )
    parser.add_argument(
        "--client-ip", default="10.0.0.2",
        help="The virtual IP the Android client's TUN is configured with (default: 10.0.0.2)"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging"
    )

    args = parser.parse_args()

    # Configure logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format=LOG_FORMAT)

    # Check root
    if not check_root():
        logger.error(
            "This server requires root access to create TUN interfaces and configure iptables.\n"
            "On Termux, run with: tsu python3 proxy_server.py\n"
            "On Linux: sudo python3 proxy_server.py"
        )
        sys.exit(1)

    logger.info("=" * 60)
    logger.info("  VPN Proxy Server — TUN-backed NAT Gateway")
    logger.info("=" * 60)
    logger.info(f"  Listen:      {args.listen}:{args.port}")
    logger.info(f"  Client IP:   {args.client_ip}")
    logger.info(f"  TUN:         {TUN_INTERFACE} ({VIRTUAL_GATEWAY}/24)")
    logger.info(f"  Max clients: {MAX_CLIENTS}")
    logger.info(f"  Ngrok:       ngrok tcp {args.port}")
    logger.info("=" * 60)

    # Store client IP
    ProxyServer.client_tunnel_ip = args.client_ip

    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        logger.info("Interrupted")


if __name__ == "__main__":
    main()
