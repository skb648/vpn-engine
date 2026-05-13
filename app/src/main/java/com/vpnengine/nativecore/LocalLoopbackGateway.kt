package com.vpnengine.nativecore

import android.util.Log
import kotlinx.coroutines.*
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap

/**
 * LocalLoopbackGateway — Embedded application-layer SOCKS5 gateway.
 *
 * This component implements the "EMBEDDED APPLICATION-LAYER GATEWAY ENGINE"
 * requirement from the architecture brief:
 *
 *   * Binds a SOCKS5-compatible stream listener on 127.0.0.1:1080
 *   * Accepts bidirectional client connections from in-app components
 *   * Forwards raw TCP payloads through ZeroTier native sockets via
 *     [ZtEngine.ztsTcpConnect] / [ZtEngine.sendToFd] / [ZtEngine.recvFromFd]
 *
 * Listening on the loopback interface guarantees that NO traffic ever
 * escapes the device through the physical network unless it has been
 * explicitly handed to libzt.so (i.e., it always uses the ZeroTier
 * virtual mesh). This eliminates the "policy loopback" trap that occurs
 * when the SDK's internal sockets are wrapped by the TUN.
 *
 * Protocol: minimal SOCKS5 CONNECT (RFC 1928), no authentication.
 *
 * NOTE: This is an OPTIONAL component. The primary VPN data plane is
 * still the TUN → libzt raw socket bridge. The loopback gateway is for
 * in-app utilities that want to push traffic explicitly through the
 * ZeroTier mesh without touching the TUN interface.
 */
class LocalLoopbackGateway(
    private val bindPort: Int = DEFAULT_PORT
) {
    companion object {
        private const val TAG = "LocalLoopbackGW"
        const val DEFAULT_PORT = 1081  // CRITICAL FIX: Changed from 1080 to avoid conflict
        // with Socks5ProxyServer which defaults to 1080. If both bind to 1080
        // (even on different interfaces), misconfiguration can create proxy loops.
        private const val BIND_HOST = "127.0.0.1"

        private const val SOCKS_VER: Byte = 0x05
        private const val NO_AUTH: Byte = 0x00
        private const val CMD_CONNECT: Byte = 0x01
        private const val ATYP_IPV4: Byte = 0x01
        private const val ATYP_DOMAIN: Byte = 0x03
        private const val REPLY_OK: Byte = 0x00
        private const val REPLY_FAIL: Byte = 0x01

        private const val BUFFER_SIZE = 16 * 1024
    }

    private var serverSocket: ServerSocket? = null
    private var scope: CoroutineScope? = null
    private val activeClients = ConcurrentHashMap.newKeySet<Socket>()

    @Volatile
    var isRunning: Boolean = false
        private set

    /**
     * Start the loopback gateway on 127.0.0.1:[bindPort].
     *
     * Returns true if the listener bound successfully.
     */
    fun start(): Boolean {
        if (isRunning) {
            Log.w(TAG, "Loopback gateway already running on $BIND_HOST:$bindPort")
            return true
        }
        return try {
            val server = ServerSocket()
            server.reuseAddress = true
            server.bind(InetSocketAddress(InetAddress.getByName(BIND_HOST), bindPort))
            serverSocket = server
            isRunning = true

            val newScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
            scope = newScope
            newScope.launch { acceptLoop(server) }

            Log.i(TAG, "Loopback gateway listening on $BIND_HOST:$bindPort")
            true
        } catch (e: IOException) {
            Log.e(TAG, "Failed to bind loopback gateway on $BIND_HOST:$bindPort", e)
            isRunning = false
            false
        }
    }

    /** Stop the gateway and tear down every active forwarding session. */
    fun stop() {
        if (!isRunning) return
        isRunning = false
        try { serverSocket?.close() } catch (_: Exception) {}
        serverSocket = null

        for (c in activeClients) {
            try { c.close() } catch (_: Exception) {}
        }
        activeClients.clear()

        try { scope?.cancel() } catch (_: Exception) {}
        scope = null
        Log.i(TAG, "Loopback gateway stopped")
    }

    private suspend fun acceptLoop(server: ServerSocket) {
        while (isRunning) {
            val client = try {
                server.accept()
            } catch (e: IOException) {
                if (isRunning) Log.w(TAG, "accept() failed: ${e.message}")
                break
            }
            client.tcpNoDelay = true
            activeClients.add(client)
            // Each accepted connection runs in its own coroutine so the
            // accept loop is never blocked by slow peers.
            scope?.launch { handleClient(client) }
        }
    }

    private suspend fun handleClient(client: Socket) {
        val input = client.getInputStream()
        val output = client.getOutputStream()
        var ztFd = -1
        try {
            // ── 1. SOCKS5 greeting ───────────────────────────────────────
            val ver = input.read()
            if (ver != SOCKS_VER.toInt() and 0xFF) {
                Log.w(TAG, "Bad SOCKS version: $ver")
                return
            }
            val nMethods = input.read()
            if (nMethods <= 0) return
            val methods = ByteArray(nMethods)
            readFully(input, methods)

            output.write(byteArrayOf(SOCKS_VER, NO_AUTH))
            output.flush()

            // ── 2. Request: VER CMD RSV ATYP DST.ADDR DST.PORT ───────────
            val header = ByteArray(4)
            readFully(input, header)
            if (header[0] != SOCKS_VER || header[1] != CMD_CONNECT) {
                writeFailure(output)
                return
            }

            val destHost: String = when (header[3]) {
                ATYP_IPV4 -> {
                    val ip = ByteArray(4); readFully(input, ip)
                    "${ip[0].toInt() and 0xFF}.${ip[1].toInt() and 0xFF}." +
                            "${ip[2].toInt() and 0xFF}.${ip[3].toInt() and 0xFF}"
                }
                ATYP_DOMAIN -> {
                    val len = input.read()
                    if (len <= 0) { writeFailure(output); return }
                    val dom = ByteArray(len); readFully(input, dom)
                    String(dom, Charsets.US_ASCII)
                }
                else -> {
                    writeFailure(output)
                    return
                }
            }
            val portBytes = ByteArray(2); readFully(input, portBytes)
            val destPort = ((portBytes[0].toInt() and 0xFF) shl 8) or
                    (portBytes[1].toInt() and 0xFF)

            Log.i(TAG, "CONNECT $destHost:$destPort via ZT native socket")

            // ── 3. Open a ZeroTier native TCP socket ─────────────────────
            ztFd = ZtEngine.ztsTcpConnect(destHost, destPort)
            if (ztFd < 0) {
                Log.w(TAG, "ztsTcpConnect failed for $destHost:$destPort")
                writeFailure(output)
                return
            }

            // ── 4. Reply success to SOCKS5 client ────────────────────────
            output.write(byteArrayOf(
                SOCKS_VER, REPLY_OK, 0x00, ATYP_IPV4,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ))
            output.flush()

            // ── 5. Bidirectional forwarding: client <→ ZT ───────────────
            coroutineScope {
                val capturedFd = ztFd
                val downstream = launch(Dispatchers.IO) {
                    val buf = ByteArray(BUFFER_SIZE)
                    while (isActive) {
                        val n = ZtEngine.recvFromFd(capturedFd, buf, buf.size)
                        if (n <= 0) break
                        try {
                            output.write(buf, 0, n)
                            output.flush()
                        } catch (_: IOException) { break }
                    }
                }
                val upstream = launch(Dispatchers.IO) {
                    val buf = ByteArray(BUFFER_SIZE)
                    while (isActive) {
                        val n = try { input.read(buf) } catch (_: IOException) { -1 }
                        if (n <= 0) break
                        val written = ZtEngine.sendToFd(capturedFd, buf, n)
                        if (written < 0) break
                    }
                }
                upstream.join()
                downstream.cancelAndJoin()
            }
        } catch (e: Exception) {
            Log.w(TAG, "Client handler error: ${e.message}")
        } finally {
            if (ztFd >= 0) {
                try { ZtEngine.closeFd(ztFd) } catch (_: Exception) {}
            }
            activeClients.remove(client)
            try { client.close() } catch (_: Exception) {}
        }
    }

    private fun writeFailure(output: java.io.OutputStream) {
        try {
            output.write(byteArrayOf(
                SOCKS_VER, REPLY_FAIL, 0x00, ATYP_IPV4,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ))
            output.flush()
        } catch (_: Exception) {}
    }

    private fun readFully(input: java.io.InputStream, dst: ByteArray) {
        var read = 0
        while (read < dst.size) {
            val n = input.read(dst, read, dst.size - read)
            if (n < 0) throw IOException("EOF while reading ${dst.size} bytes")
            read += n
        }
    }
}
