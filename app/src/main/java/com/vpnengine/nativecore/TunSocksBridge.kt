package com.vpnengine.nativecore

import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress

/**
 * TunSocksBridge — The main TUN-to-SOCKS5 bridge for RECEIVER (Full Tunneling) mode.
 *
 * This class implements the complete user-space packet processing pipeline:
 *
 *   ┌─────────────────────────────────────────────────────────────────┐
 *   │                    RECEIVER MODE ARCHITECTURE                   │
 *   │                                                                 │
 *   │  Device Apps                                                    │
 *   │      ↓                                                          │
 *   │  Android TUN (0.0.0.0/0)                                       │
 *   │      ↓  raw IP packets                                          │
 *   │  TunSocksBridge.readLoop()                                      │
 *   │      ↓  parsed packets                                          │
 *   │  TcpConnectionManager                                           │
 *   │      ↓  SOCKS5 CONNECT requests                                 │
 *   │  ZtSocks5Client                                                 │
 *   │      ↓  ZT TCP socket connections                               │
 *   │  libzt (ZeroTier SDK)                                           │
 *   │      ↓  encrypted P2P traffic                                   │
 *   │  Sender's SOCKS5 Proxy (Exit Node)                              │
 *   │      ↓                                                          │
 *   │  Internet                                                       │
 *   └─────────────────────────────────────────────────────────────────┘
 *
 * CRITICAL DESIGN DECISIONS:
 *
 * 1. NO ROOT REQUIRED: All packet processing happens in user space.
 *    The VpnService TUN interface provides raw IP packets, and we
 *    parse them, track TCP connections, and route through SOCKS5
 *    proxy connections — no iptables NAT needed.
 *
 * 2. HYBRID ROUTING: TCP traffic goes through the SOCKS5 proxy chain
 *    (local → ZT socket → Sender's SOCKS5 → internet), while UDP
 *    traffic is forwarded through the existing C++ ZT raw socket bridge.
 *    This gives us the best of both worlds: reliable TCP proxying with
 *    SOCKS5, and efficient UDP forwarding via raw sockets.
 *
 * 3. ZT SOCKET BINDING: On Android 11+ (API 30+), we use
 *    bindProcessToNetwork() to ensure ZeroTier SDK sockets can access
 *    the physical network. The SOCKS5 proxy connections are created
 *    through ZtEngine.ztsTcpConnect() which uses the native ZT socket
 *    API, ensuring traffic routes through the ZeroTier virtual network.
 *
 * 4. DNS INTERCEPTION: DNS queries (UDP port 53) are intercepted and
 *    can be resolved through the SOCKS5 proxy to prevent DNS leaks.
 *    Alternatively, DNS can be forwarded through the ZeroTier network
 *    using the C++ raw socket bridge.
 */
class TunSocksBridge(
    private val vpnService: VpnService,
    private val pfd: ParcelFileDescriptor
) {
    companion object {
        private const val TAG = "TunSocksBridge"
        private const val TUN_MTU = 1500
        private const val READ_BUFFER_SIZE = TUN_MTU + 64  // Extra space for headers
        private const val STATS_INTERVAL_MS = 10_000L
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @Volatile
    private var running = false

    private var readJob: Job? = null
    private var statsJob: Job? = null
    private var tunInput: FileInputStream? = null
    private var tunOutput: FileOutputStream? = null

    // TCP connection manager with SOCKS5 proxy bridge
    private lateinit var connectionManager: TcpConnectionManager

    // Traffic statistics
    @Volatile
    var packetsRead = 0L
        private set

    @Volatile
    var packetsWritten = 0L
        private set

    @Volatile
    var bytesIn = 0L
        private set

    @Volatile
    var bytesOut = 0L
        private set

    @Volatile
    var tcpConnectionsOpened = 0L
        private set

    @Volatile
    var tcpConnectionsActive = 0
        private set

    /**
     * Start the TUN-to-SOCKS5 bridge.
     *
     * @param exitNodeAddress The Sender/Exit Node's ZeroTier virtual IP address
     * @param exitNodePort The Sender's SOCKS5 proxy port (default 1080)
     */
    fun start(exitNodeAddress: String, exitNodePort: Int = 1080): Boolean {
        if (running) {
            Log.w(TAG, "TUN-SOCKS bridge already running")
            return true
        }

        if (exitNodeAddress.isBlank()) {
            Log.e(TAG, "Exit node address is empty — cannot start TUN-SOCKS bridge")
            return false
        }

        try {
            tunInput = FileInputStream(pfd.fileDescriptor)
            tunOutput = FileOutputStream(pfd.fileDescriptor)

            // Initialize TCP connection manager with TUN write callback
            connectionManager = TcpConnectionManager(vpnService, scope) { packet ->
                writePacketToTun(packet)
            }
            connectionManager.configureExitNode(exitNodeAddress, exitNodePort)

            running = true

            // Start the main TUN read loop
            readJob = scope.launch {
                tunReadLoop()
            }

            // Start stats reporting
            statsJob = scope.launch {
                statsLoop()
            }

            Log.i(TAG, "TUN-SOCKS bridge started (exit node: $exitNodeAddress:$exitNodePort)")
            return true

        } catch (e: Exception) {
            Log.e(TAG, "Failed to start TUN-SOCKS bridge", e)
            stop()
            return false
        }
    }

    /**
     * Stop the TUN-SOCKS bridge and clean up all resources.
     */
    fun stop() {
        if (!running) return
        running = false

        Log.i(TAG, "Stopping TUN-SOCKS bridge...")

        readJob?.cancel()
        statsJob?.cancel()

        if (::connectionManager.isInitialized) {
            connectionManager.closeAll()
        }

        try {
            tunInput?.close()
        } catch (_: Exception) {}
        tunInput = null

        try {
            tunOutput?.close()
        } catch (_: Exception) {}
        tunOutput = null

        scope.cancel()

        Log.i(TAG, "TUN-SOCKS bridge stopped (packets read=$packetsRead, written=$packetsWritten)")
    }

    /**
     * Main TUN read loop — reads raw IP packets and routes them.
     *
     * This is the heart of the user-space packet processing pipeline.
     * Every packet read from the TUN interface is:
     *   1. Parsed into a structured ParsedPacket
     *   2. Routed based on protocol:
     *      - TCP → TcpConnectionManager (SOCKS5 proxy bridge)
     *      - UDP → Forwarded through C++ ZT raw socket bridge
     *      - ICMP → Logged and dropped (not proxied)
     */
    private suspend fun tunReadLoop() {
        val buffer = ByteArray(READ_BUFFER_SIZE)

        Log.i(TAG, "TUN read loop started")

        try {
            while (running && scope.isActive) {
                val bytesRead = tunInput?.read(buffer) ?: -1
                if (bytesRead < 0) {
                    if (!running) break
                    Log.w(TAG, "TUN read returned $bytesRead — EOF or error")
                    delay(10)
                    continue
                }

                if (bytesRead == 0) continue

                packetsRead++
                bytesIn += bytesRead

                // Parse the IP packet
                val packet = IpPacketParser.parse(buffer, bytesRead)
                if (packet == null) {
                    // Malformed packet — drop silently
                    continue
                }

                // Route based on protocol
                when (packet.protocol) {
                    IpPacketParser.PROTOCOL_TCP -> {
                        connectionManager.processTcpPacket(packet)
                        tcpConnectionsActive = connectionManager.connectionCount
                    }
                    IpPacketParser.PROTOCOL_UDP -> {
                        connectionManager.processUdpPacket(packet)
                        // UDP is forwarded through the C++ ZT raw socket bridge
                    }
                    IpPacketParser.PROTOCOL_ICMP -> {
                        // ICMP not proxied through SOCKS5 — drop
                        Log.d(TAG, "ICMP packet dropped: ${packet.sourceAddress} → ${packet.destinationAddress}")
                    }
                }
            }
        } catch (e: CancellationException) {
            // Normal — coroutine cancelled during shutdown
        } catch (e: Exception) {
            if (running) {
                Log.e(TAG, "Fatal error in TUN read loop", e)
            }
        } finally {
            Log.i(TAG, "TUN read loop ended")
        }
    }

    /**
     * Write a raw IP packet to the TUN interface.
     * Used by TcpConnectionManager to send TCP responses back to apps.
     */
    private fun writePacketToTun(packet: ByteArray) {
        try {
            tunOutput?.write(packet)
            packetsWritten++
            bytesOut += packet.size
        } catch (e: Exception) {
            if (running) {
                Log.w(TAG, "Failed to write packet to TUN: ${e.message}")
            }
        }
    }

    /**
     * Periodic stats reporting loop.
     */
    private suspend fun statsLoop() {
        while (running && scope.isActive) {
            delay(STATS_INTERVAL_MS)
            val activeConns = if (::connectionManager.isInitialized) connectionManager.connectionCount else 0
            Log.i(TAG, "Stats: pkts_in=$packetsRead pkts_out=$packetsWritten " +
                    "bytes_in=$bytesIn bytes_out=$bytesOut active_conns=$activeConns")

            // Update VpnStateHolder traffic stats
            VpnStateHolder.updateTrafficStats(bytesIn, bytesOut, packetsRead, packetsWritten)
        }
    }
}
