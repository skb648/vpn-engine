package com.vpnengine.nativecore

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap

/**
 * Socks5ProxyServer — Lightweight user-space SOCKS5 proxy for Sender mode.
 *
 * When the app is in SENDER mode, this proxy server:
 *   1. Binds to the ZeroTier virtual IP address (e.g., 10.147.20.x)
 *   2. Listens for SOCKS5 connection requests from ZeroTier peers
 *   3. Forwards TCP connections to the actual internet
 *
 * This enables Receiver-mode peers to access the internet through
 * the Sender's ZeroTier virtual IP.
 *
 * SOCKS5 Protocol (RFC 1928) — Simplified implementation:
 *   - No authentication (ZeroTier network provides security layer)
 *   - CONNECT command only (TCP)
 *   - IPv4 and domain name addressing supported
 *
 * Usage:
 *   val proxy = Socks5ProxyServer(ztIpAddress, 1080)
 *   proxy.start()   // Starts listening in a coroutine
 *   proxy.stop()    // Graceful shutdown
 */
class Socks5ProxyServer(
    private val bindAddress: String,
    private val bindPort: Int = DEFAULT_PORT,
    private val vpnService: VpnService? = null
) {
    companion object {
        private const val TAG = "Socks5Proxy"
        private const val DEFAULT_PORT = 1080

        // SOCKS5 protocol constants
        private const val SOCKS_VERSION = 0x05.toByte()
        private const val AUTH_NONE = 0x00.toByte()
        private const val AUTH_NO_ACCEPTABLE = 0xFF.toByte()
        private const val CMD_CONNECT = 0x01.toByte()
        private const val ATYP_IPV4 = 0x01.toByte()
        private const val ATYP_DOMAIN = 0x03.toByte()
        private const val ATYP_IPV6 = 0x04.toByte()
        private const val REPLY_SUCCESS = 0x00.toByte()
        private const val REPLY_GENERAL_FAILURE = 0x01.toByte()
        private const val REPLY_CONNECTION_NOT_ALLOWED = 0x02.toByte()
        private const val REPLY_NETWORK_UNREACHABLE = 0x03.toByte()
        private const val REPLY_HOST_UNREACHABLE = 0x04.toByte()
        private const val REPLY_CONNECTION_REFUSED = 0x05.toByte()
    }

    private var serverSocket: ServerSocket? = null
    private var scope: CoroutineScope? = null
    private var acceptJob: Job? = null

    @Volatile
    var isRunning = false
        private set

    // BUG FIX: Use ConcurrentHashMap.newKeySet() instead of mutableSetOf()
    // for thread-safe concurrent access. The accept loop and handler coroutines
    // run on different threads and both add/remove from this set.
    private val activeConnections = ConcurrentHashMap.newKeySet<Socket>()

    /**
     * Start the SOCKS5 proxy server. Binds to [bindAddress]:[bindPort]
     * and begins accepting connections in a coroutine.
     *
     * @return true if the server started successfully.
     */
    fun start(): Boolean {
        if (isRunning) {
            Log.w(TAG, "Proxy already running on $bindAddress:$bindPort")
            return true
        }

        return try {
            val inetAddr = InetAddress.getByName(bindAddress)
            serverSocket = ServerSocket().apply {
                reuseAddress = true
                bind(InetSocketAddress(inetAddr, bindPort))
            }
            scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
            isRunning = true

            acceptJob = scope?.launch {
                Log.i(TAG, "SOCKS5 proxy listening on $bindAddress:$bindPort")
                while (isActive && isRunning) {
                    try {
                        val clientSocket = serverSocket?.accept() ?: break
                        clientSocket.tcpNoDelay = true
                        clientSocket.soTimeout = 30_000 // 30s handshake timeout

                        activeConnections.add(clientSocket)

                        scope?.launch { handleClient(clientSocket) }
                    } catch (e: IOException) {
                        if (isRunning) Log.w(TAG, "Accept error: ${e.message}")
                    }
                }
            }

            Log.i(TAG, "SOCKS5 proxy started on $bindAddress:$bindPort")
            VpnStateHolder.updateSocks5ProxyRunning(true)
            true

        } catch (e: IOException) {
            Log.e(TAG, "Failed to start SOCKS5 proxy on $bindAddress:$bindPort", e)
            isRunning = false
            VpnStateHolder.updateSocks5ProxyRunning(false)
            false
        }
    }

    /**
     * Stop the SOCKS5 proxy server gracefully.
     * Closes all active connections and the server socket.
     */
    fun stop() {
        if (!isRunning) return
        isRunning = false
        VpnStateHolder.updateSocks5ProxyRunning(false)

        try {
            acceptJob?.cancel()
        } catch (_: Exception) {}

            for (socket in activeConnections) {
                try { socket.close() } catch (_: Exception) {}
            }
            activeConnections.clear()

        try {
            serverSocket?.close()
        } catch (e: IOException) {
            Log.w(TAG, "Error closing server socket: ${e.message}")
        }
        serverSocket = null

        try {
            scope?.cancel()
        } catch (_: Exception) {}
        scope = null

        Log.i(TAG, "SOCKS5 proxy stopped")
    }

    /**
     * Handle a single SOCKS5 client connection.
     * 1. Perform SOCKS5 handshake (method selection)
     * 2. Read the CONNECT request
     * 3. Establish the outgoing connection
     * 4. Bridge data bidirectionally
     */
    private suspend fun handleClient(client: Socket) {
        val clientAddr = client.remoteSocketAddress
        Log.d(TAG, "New connection from $clientAddr")

        try {
            val input = client.getInputStream()
            val output = client.getOutputStream()

            // ── Step 1: SOCKS5 Method Selection ────────────────────────
            if (!performHandshake(input, output)) {
                Log.w(TAG, "SOCKS5 handshake failed from $clientAddr")
                client.close()
                return
            }

            // ── Step 2: Read CONNECT Request ───────────────────────────
            val request = readConnectRequest(input) ?: run {
                Log.w(TAG, "Invalid CONNECT request from $clientAddr")
                sendReply(output, REPLY_GENERAL_FAILURE)
                client.close()
                return
            }

            if (request.command != CMD_CONNECT) {
                Log.w(TAG, "Unsupported SOCKS5 command: ${request.command} from $clientAddr")
                sendReply(output, REPLY_CONNECTION_NOT_ALLOWED)
                client.close()
                return
            }

            // ── Step 3: Connect to Target ──────────────────────────────
            val targetSocket = connectToTarget(request)
            if (targetSocket == null) {
                Log.w(TAG, "Failed to connect to ${request.host}:${request.port}")
                sendReply(output, REPLY_CONNECTION_REFUSED)
                client.close()
                return
            }

            // ── Step 4: Send Success Reply ─────────────────────────────
            val boundAddr = targetSocket.localAddress.address
            val boundPort = targetSocket.localPort
            val bindAddrBytes = byteArrayOf(ATYP_IPV4) + boundAddr +
                    byteArrayOf((boundPort shr 8).toByte(), boundPort.toByte())
            sendReply(output, REPLY_SUCCESS, bindAddrBytes)

            // ── Step 5: Bridge Data ────────────────────────────────────
            client.soTimeout = 0 // Remove timeout for data transfer
            bridgeData(client, targetSocket)

        } catch (e: IOException) {
            Log.d(TAG, "Connection error from $clientAddr: ${e.message}")
        } catch (e: Exception) {
            Log.w(TAG, "Unexpected error handling $clientAddr", e)
        } finally {
            try { client.close() } catch (_: Exception) {}
            activeConnections.remove(client)
        }
    }

    /**
     * Perform the SOCKS5 method selection handshake.
     * We only support NO AUTH (0x00).
     */
    private fun performHandshake(input: InputStream, output: OutputStream): Boolean {
        // Read: VER (1) | NMETHODS (1) | METHODS (NMETHODS)
        val ver = input.read()
        if (ver != SOCKS_VERSION.toInt()) {
            Log.w(TAG, "Invalid SOCKS version: $ver")
            return false
        }

        val nMethods = input.read()
        if (nMethods <= 0 || nMethods > 255) {
            Log.w(TAG, "Invalid NMETHODS: $nMethods")
            return false
        }

        val methods = ByteArray(nMethods)
        input.readFully(methods)

        // Check if NO AUTH is supported
        val noAuthSupported = methods.contains(AUTH_NONE)

        // Reply: VER (1) | METHOD (1)
        val reply = if (noAuthSupported) {
            byteArrayOf(SOCKS_VERSION, AUTH_NONE)
        } else {
            byteArrayOf(SOCKS_VERSION, AUTH_NO_ACCEPTABLE)
        }
        output.write(reply)
        output.flush()

        return noAuthSupported
    }

    /**
     * Read the SOCKS5 CONNECT request.
     * Returns a ConnectRequest or null on parse error.
     */
    private fun readConnectRequest(input: InputStream): ConnectRequest? {
        // Read: VER (1) | CMD (1) | RSV (1) | ATYP (1)
        val ver = input.read()
        if (ver != SOCKS_VERSION.toInt()) return null

        val cmd = input.read().toByte()
        input.read() // RSV (reserved, must be 0x00)

        val atyp = input.read().toByte()

        val host: String = when (atyp) {
            ATYP_IPV4 -> {
                val addr = ByteArray(4)
                input.readFully(addr)
                InetAddress.getByAddress(addr).hostAddress ?: return null
            }
            ATYP_DOMAIN -> {
                val domainLen = input.read()
                if (domainLen <= 0) return null
                val domain = ByteArray(domainLen)
                input.readFully(domain)
                String(domain)
            }
            ATYP_IPV6 -> {
                val addr = ByteArray(16)
                input.readFully(addr)
                InetAddress.getByAddress(addr).hostAddress ?: return null
            }
            else -> {
                Log.w(TAG, "Unsupported ATYP: $atyp")
                return null
            }
        }

        val portHi = input.read()
        val portLo = input.read()
        val port = (portHi shl 8) or portLo

        return ConnectRequest(cmd, atyp, host, port)
    }

    /**
     * Connect to the target host:port specified in the SOCKS5 request.
     * CRITICAL FIX: Support both IPv4 and IPv6 targets.
     */
    private fun connectToTarget(request: ConnectRequest): Socket? {
        return try {
            // CRITICAL FIX: Detect IPv6 and create appropriate socket
            val address = InetAddress.getByName(request.host)
            val socket = when (address) {
                is java.net.Inet6Address -> {
                    // IPv6 target — explicitly create IPv6 socket
                    Log.d(TAG, "Connecting to IPv6 target: ${request.host}:${request.port}")
                    Socket()
                }
                else -> {
                    // IPv4 target (or hostname resolved to IPv4)
                    Socket()
                }
            }
            socket.tcpNoDelay = true
            // Protect the socket from routing through any VPN tunnel.
            // This is critical when another VPN is active on the device —
            // without protect(), the outgoing connection would route through
            // that VPN instead of the real internet.
            vpnService?.protect(socket)
            socket.connect(InetSocketAddress(request.host, request.port), 15_000)
            socket
        } catch (e: IOException) {
            Log.d(TAG, "Cannot connect to ${request.host}:${request.port}: ${e.message}")
            null
        }
    }

    /**
     * Send a SOCKS5 reply to the client.
     */
    private fun sendReply(output: OutputStream, replyCode: Byte, bindAddr: ByteArray = byteArrayOf()) {
        // VER (1) | REP (1) | RSV (1) | ATYP (1) | BND.ADDR | BND.PORT
        val reply = byteArrayOf(SOCKS_VERSION, replyCode, 0x00.toByte()) +
                if (bindAddr.isNotEmpty()) bindAddr
                else byteArrayOf(ATYP_IPV4, 0, 0, 0, 0, 0, 0)
        output.write(reply)
        output.flush()
    }

    /**
     * Bridge data between the client and target sockets.
     * Uses two coroutines for bidirectional forwarding.
     */
    private suspend fun bridgeData(client: Socket, target: Socket) {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

        try {
            val clientToTarget = scope.async {
                val buf = ByteArray(8192)
                val input = client.getInputStream()
                val output = target.getOutputStream()
                while (isActive) {
                    val n = input.read(buf)
                    if (n < 0) break
                    if (n > 0) output.write(buf, 0, n)
                    output.flush()
                }
            }

            val targetToClient = scope.async {
                val buf = ByteArray(8192)
                val input = target.getInputStream()
                val output = client.getOutputStream()
                while (isActive) {
                    val n = input.read(buf)
                    if (n < 0) break
                    if (n > 0) output.write(buf, 0, n)
                    output.flush()
                }
            }

            // Wait for either direction to close
            try {
                awaitAll(clientToTarget, targetToClient)
            } catch (_: Exception) {
                // One side closed — cancel the other
            }
        } catch (e: IOException) {
            // Normal — one side closed the connection
        } catch (e: CancellationException) {
            // Normal — coroutine cancelled during shutdown
        } finally {
            scope.cancel()
            try { target.close() } catch (_: Exception) {}
        }
    }

    private fun InputStream.readFully(buf: ByteArray) {
        var offset = 0
        while (offset < buf.size) {
            val n = read(buf, offset, buf.size - offset)
            if (n < 0) throw IOException("Unexpected end of stream")
            offset += n
        }
    }

    private data class ConnectRequest(
        val command: Byte,
        val addressType: Byte,
        val host: String,
        val port: Int
    )
}
