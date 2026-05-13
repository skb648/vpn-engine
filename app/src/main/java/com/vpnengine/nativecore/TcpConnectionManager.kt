package com.vpnengine.nativecore

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.ConcurrentHashMap

/**
 * TcpConnectionManager — User-space TCP connection tracker and SOCKS5 proxy bridge.
 *
 * In RECEIVER (Full Tunneling) mode, this class:
 *   1. Tracks all active TCP connections by their 4-tuple (src_ip:port, dst_ip:port)
 *   2. For each new TCP SYN from the TUN interface, establishes a SOCKS5 connection
 *      through the ZeroTier virtual network to the Sender/Exit Node's proxy
 *   3. Bridges TCP data bidirectionally between TUN and SOCKS5 proxy
 *   4. Handles TCP state transitions (SYN, ACK, FIN, RST) in user space
 *   5. Generates appropriate TCP response packets to write back to TUN
 *
 * Why this is needed WITHOUT root:
 *   - Without root, we cannot use iptables NAT rules to forward traffic
 *   - Android VpnService captures all traffic as raw IP packets via TUN
 *   - We must parse, track, and forward TCP connections in user space
 *   - The SOCKS5 proxy chain provides the NAT functionality at the application layer
 *
 * Architecture:
 *   TUN Packet → Parse → Track Connection → SOCKS5 via ZT → Sender's Proxy → Internet
 *   TUN Packet ← Build ← Translate Response ← SOCKS5 via ZT ← Sender's Proxy ← Internet
 */
class TcpConnectionManager(
    private val vpnService: VpnService,
    private val scope: CoroutineScope,
    private val tunWriter: (ByteArray) -> Unit
) {
    companion object {
        private const val TAG = "TcpConnManager"
        private const val MAX_CONNECTIONS = 256
        private const val CONNECTION_TIMEOUT_MS = 120_000L  // 2 minutes
        private const val BUFFER_SIZE = 32768
    }

    /**
     * Represents a tracked TCP connection with SOCKS5 proxy bridge.
     *
     * @param srcAddress Source IP (VPN interface IP)
     * @param srcPort Source port (app's port)
     * @param dstAddress Destination IP (target server)
     * @param dstPort Destination port (target server port)
     * @param socks5Connection The established SOCKS5 connection through ZT
     * @param seqNumber Current sequence number for sending to TUN
     * @param ackNumber Current acknowledgment number for sending to TUN
     * @param clientSeqNumber Last seen sequence number from client (TUN)
     * @param clientAckNumber Last seen acknowledgment number from client (TUN)
     */
    data class TcpConnection(
        val srcAddress: String,
        val srcPort: Int,
        val dstAddress: String,
        val dstPort: Int,
        val socks5Connection: ZtSocks5Client.Socks5Connection,
        var seqNumber: Long,
        var ackNumber: Long,
        var clientSeqNumber: Long,
        var clientAckNumber: Long,
        var state: TcpState = TcpState.SYN_RECEIVED,
        var lastActivityMs: Long = System.currentTimeMillis(),
        val bridgeJob: Job? = null
    )

    enum class TcpState {
        SYN_RECEIVED,     // We received SYN, sent SYN-ACK
        ESTABLISHED,      // Connection fully established
        CLOSE_WAIT,       // Remote side initiated close
        LAST_ACK,         // Our FIN sent, waiting for final ACK
        CLOSED            // Connection fully closed
    }

    private val socks5Client = ZtSocks5Client(vpnService)
    private val connections = ConcurrentHashMap<String, TcpConnection>()
    private val connectionMutex = Mutex()
    private var exitNodeAddress: String = ""
    private var exitNodePort: Int = 1080

    /**
     * Configure the exit node (Sender) SOCKS5 proxy address.
     * Must be called before processing any packets.
     */
    fun configureExitNode(address: String, port: Int = 1080) {
        exitNodeAddress = address
        exitNodePort = port
        Log.i(TAG, "Exit node configured: $address:$port")
    }

    /**
     * Process a parsed TCP packet from the TUN interface.
     *
     * This is the main entry point for the TUN-to-SOCKS5 bridge.
     * It handles TCP state transitions and data forwarding.
     */
    suspend fun processTcpPacket(packet: IpPacketParser.ParsedPacket) {
        val key = packet.connectionKey

        try {
            when {
                packet.isSyn && !packet.isAck -> {
                    // New connection — SYN received
                    handleNewConnection(packet, key)
                }
                packet.isRst -> {
                    // RST — close connection immediately
                    handleRst(key)
                }
                packet.isFin -> {
                    // FIN — graceful close
                    handleFin(packet, key)
                }
                packet.isAck && packet.payloadLength > 0 -> {
                    // Data packet with ACK
                    handleDataPacket(packet, key)
                }
                packet.isAck -> {
                    // Pure ACK (no data) — update sequence tracking
                    handlePureAck(packet, key)
                }
                else -> {
                    Log.d(TAG, "Unhandled TCP flags: ${packet.tcpFlags} for $key")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error processing TCP packet for $key: ${e.message}")
        }
    }

    /**
     * Process a UDP packet from the TUN interface.
     * For UDP, we don't track connections — we forward through the C++ ZT bridge.
     */
    fun processUdpPacket(packet: IpPacketParser.ParsedPacket) {
        // UDP forwarding is handled by the C++ TUN bridge (zts_bsd_sendto)
        // We just log it here for diagnostics
        Log.d(TAG, "UDP packet: ${packet.sourceAddress}:${packet.sourcePort} -> " +
                "${packet.destinationAddress}:${packet.destinationPort} (${packet.payloadLength} bytes)")
    }

    /**
     * Handle new TCP connection (SYN packet from TUN).
     * Establishes a SOCKS5 connection through the ZeroTier network.
     */
    private suspend fun handleNewConnection(packet: IpPacketParser.ParsedPacket, key: String) {
        if (connections.size >= MAX_CONNECTIONS) {
            Log.w(TAG, "Max connections reached ($MAX_CONNECTIONS) — dropping SYN for $key")
            sendRst(packet)
            return
        }

        if (exitNodeAddress.isBlank()) {
            Log.e(TAG, "Exit node not configured — dropping SYN for $key")
            sendRst(packet)
            return
        }

        connectionMutex.withLock {
            if (connections.containsKey(key)) {
                Log.w(TAG, "Duplicate SYN for existing connection: $key")
                return
            }
        }

        Log.i(TAG, "New TCP connection: ${packet.destinationAddress}:${packet.destinationPort} via exit node $exitNodeAddress")

        // Send SYN-ACK to the client immediately (before proxy connection is ready)
        // This keeps the TCP handshake going while we establish the SOCKS5 connection
        val initialSeq = System.currentTimeMillis() and 0xFFFFFFFFL  // Random-ish initial sequence
        sendSynAck(packet, initialSeq, packet.tcpSeqNumber + 1)

        // Establish SOCKS5 connection through ZeroTier to the exit node
        val socks5Conn = socks5Client.connectThroughProxy(
            proxyAddress = exitNodeAddress,
            proxyPort = exitNodePort,
            targetHost = packet.destinationAddress,
            targetPort = packet.destinationPort
        )

        if (socks5Conn == null) {
            Log.e(TAG, "Failed to establish SOCKS5 connection for $key — sending RST")
            sendRst(packet)
            return
        }

        val conn = TcpConnection(
            srcAddress = packet.sourceAddress,
            srcPort = packet.sourcePort,
            dstAddress = packet.destinationAddress,
            dstPort = packet.destinationPort,
            socks5Connection = socks5Conn,
            seqNumber = initialSeq + 1,  // After SYN-ACK
            ackNumber = packet.tcpSeqNumber + 1,  // After receiving SYN
            clientSeqNumber = packet.tcpSeqNumber + 1,
            clientAckNumber = initialSeq + 1,
            state = TcpState.SYN_RECEIVED
        )

        connections[key] = conn

        // Start the proxy-to-TUN bridge coroutine
        // This reads data from the SOCKS5 proxy and writes it back to TUN
        val bridgeJob = scope.launch(Dispatchers.IO) {
            bridgeProxyToTun(key, conn)
        }
        connections[key] = conn.copy(bridgeJob = bridgeJob)

        Log.i(TAG, "SOCKS5 bridge established for $key (conn count: ${connections.size})")
    }

    /**
     * Handle TCP data packet (ACK with payload).
     * Forwards data through the SOCKS5 proxy to the exit node.
     */
    private suspend fun handleDataPacket(packet: IpPacketParser.ParsedPacket, key: String) {
        val conn = connections[key]
        if (conn == null) {
            Log.w(TAG, "Data packet for unknown connection: $key — sending RST")
            sendRst(packet)
            return
        }

        conn.lastActivityMs = System.currentTimeMillis()

        // Forward payload to SOCKS5 proxy
        if (packet.payloadLength > 0) {
            val payload = packet.tcpPayload
            val written = conn.socks5Connection.write(payload)
            if (written < 0) {
                Log.w(TAG, "Failed to write to SOCKS5 connection for $key")
                closeConnection(key)
                return
            }

            // Update tracking
            conn.clientSeqNumber = packet.tcpSeqNumber + packet.payloadLength
            conn.ackNumber = conn.clientSeqNumber

            // Send ACK back to client
            sendAck(conn)
        }
    }

    /**
     * Handle pure ACK packet (no data).
     * Updates sequence tracking and connection state.
     */
    private fun handlePureAck(packet: IpPacketParser.ParsedPacket, key: String) {
        val conn = connections[key] ?: return
        conn.lastActivityMs = System.currentTimeMillis()
        conn.clientAckNumber = packet.tcpAckNumber

        // If we were in SYN_RECEIVED and got an ACK, we're now ESTABLISHED
        if (conn.state == TcpState.SYN_RECEIVED) {
            conn.state = TcpState.ESTABLISHED
            Log.d(TAG, "Connection ESTABLISHED: $key")
        }
    }

    /**
     * Handle FIN packet (graceful close from client).
     */
    private suspend fun handleFin(packet: IpPacketParser.ParsedPacket, key: String) {
        val conn = connections[key]
        if (conn == null) {
            Log.w(TAG, "FIN for unknown connection: $key")
            return
        }

        Log.d(TAG, "FIN received for $key (state=${conn.state})")

        // Send FIN-ACK back to client
        conn.ackNumber = packet.tcpSeqNumber + 1
        sendFinAck(conn)

        // Close SOCKS5 connection
        closeConnection(key)
    }

    /**
     * Handle RST packet (immediate close).
     */
    private fun handleRst(key: String) {
        Log.d(TAG, "RST received for $key")
        closeConnection(key)
    }

    /**
     * Bridge data from the SOCKS5 proxy back to the TUN interface.
     * Runs in a coroutine for each active connection.
     */
    private suspend fun bridgeProxyToTun(key: String, conn: TcpConnection) {
        val buffer = ByteArray(BUFFER_SIZE)

        try {
            while (conn.state != TcpState.CLOSED && scope.isActive) {
                val bytesRead = conn.socks5Connection.read(buffer)
                if (bytesRead < 0) {
                    // Connection closed by proxy
                    Log.d(TAG, "Proxy connection closed for $key")
                    break
                }
                if (bytesRead == 0) {
                    delay(1)  // Small yield to prevent busy loop
                    continue
                }

                // Build TCP data packet and write to TUN
                val data = buffer.copyOf(bytesRead)
                val tcpPacket = IpPacketParser.buildTcpPacket(
                    srcAddr = conn.dstAddress,
                    dstAddr = conn.srcAddress,
                    srcPort = conn.dstPort,
                    dstPort = conn.srcPort,
                    seqNum = conn.seqNumber,
                    ackNum = conn.ackNumber,
                    flags = IpPacketParser.TCP_FLAG_PSH or IpPacketParser.TCP_FLAG_ACK,
                    windowSize = 65535,
                    payload = data
                )

                tunWriter(tcpPacket)
                conn.seqNumber += bytesRead
                conn.lastActivityMs = System.currentTimeMillis()
            }
        } catch (e: CancellationException) {
            // Normal — coroutine cancelled during shutdown
        } catch (e: Exception) {
            Log.d(TAG, "Proxy bridge error for $key: ${e.message}")
        } finally {
            if (conn.state != TcpState.CLOSED) {
                sendFinAck(conn)
                closeConnection(key)
            }
        }
    }

    /**
     * Send a TCP SYN-ACK packet back to the TUN interface.
     */
    private fun sendSynAck(originalPacket: IpPacketParser.ParsedPacket, seqNum: Long, ackNum: Long) {
        val synAck = IpPacketParser.buildTcpPacket(
            srcAddr = originalPacket.destinationAddress,
            dstAddr = originalPacket.sourceAddress,
            srcPort = originalPacket.destinationPort,
            dstPort = originalPacket.sourcePort,
            seqNum = seqNum,
            ackNum = ackNum,
            flags = IpPacketParser.TCP_FLAG_SYN or IpPacketParser.TCP_FLAG_ACK,
            windowSize = 65535
        )
        tunWriter(synAck)
    }

    /**
     * Send a TCP ACK packet back to the TUN interface.
     */
    private fun sendAck(conn: TcpConnection) {
        val ack = IpPacketParser.buildTcpPacket(
            srcAddr = conn.dstAddress,
            dstAddr = conn.srcAddress,
            srcPort = conn.dstPort,
            dstPort = conn.srcPort,
            seqNum = conn.seqNumber,
            ackNum = conn.ackNumber,
            flags = IpPacketParser.TCP_FLAG_ACK,
            windowSize = 65535
        )
        tunWriter(ack)
    }

    /**
     * Send a TCP FIN-ACK packet back to the TUN interface.
     */
    private fun sendFinAck(conn: TcpConnection) {
        val finAck = IpPacketParser.buildTcpPacket(
            srcAddr = conn.dstAddress,
            dstAddr = conn.srcAddress,
            srcPort = conn.dstPort,
            dstPort = conn.srcPort,
            seqNum = conn.seqNumber,
            ackNum = conn.ackNumber,
            flags = IpPacketParser.TCP_FLAG_FIN or IpPacketParser.TCP_FLAG_ACK,
            windowSize = 65535
        )
        tunWriter(finAck)
    }

    /**
     * Send a TCP RST packet back to the TUN interface.
     */
    private fun sendRst(originalPacket: IpPacketParser.ParsedPacket) {
        val rst = IpPacketParser.buildTcpPacket(
            srcAddr = originalPacket.destinationAddress,
            dstAddr = originalPacket.sourceAddress,
            srcPort = originalPacket.destinationPort,
            dstPort = originalPacket.sourcePort,
            seqNum = 0,
            ackNum = 0,
            flags = IpPacketParser.TCP_FLAG_RST,
            windowSize = 0
        )
        tunWriter(rst)
    }

    /**
     * Close a tracked connection and clean up resources.
     */
    private fun closeConnection(key: String) {
        val conn = connections.remove(key)
        if (conn != null) {
            try {
                conn.bridgeJob?.cancel()
            } catch (_: Exception) {}
            try {
                conn.socks5Connection.close()
            } catch (_: Exception) {}
            Log.d(TAG, "Connection closed: $key (remaining: ${connections.size})")
        }
    }

    /**
     * Close all tracked connections and clean up.
     */
    fun closeAll() {
        Log.i(TAG, "Closing all connections (${connections.size})")
        for ((key, conn) in connections) {
            try {
                conn.bridgeJob?.cancel()
            } catch (_: Exception) {}
            try {
                conn.socks5Connection.close()
            } catch (_: Exception) {}
        }
        connections.clear()
    }

    /**
     * Get the number of active connections.
     */
    val connectionCount: Int get() = connections.size

    /**
     * Check if a connection exists for the given key.
     */
    fun hasConnection(key: String): Boolean = connections.containsKey(key)
}
