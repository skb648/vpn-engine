package com.vpnengine.nativecore

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.*
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/**
 * ZtSocks5Client — SOCKS5 client that connects through ZeroTier sockets
 * to the Sender/Exit Node's SOCKS5 proxy.
 *
 * In RECEIVER (Full Tunneling) mode, this client:
 *   1. Creates a TCP socket through the ZeroTier virtual network
 *   2. Connects to the Sender's SOCKS5 proxy running on the ZT virtual IP
 *   3. Sends a SOCKS5 CONNECT request for the target host:port
 *   4. Bridges data between the TUN connection and the proxy connection
 *
 * SOCKS5 Protocol (RFC 1928) — Client side:
 *   1. Client sends: VER(0x05) | NMETHODS(0x01) | METHOD(0x00=no-auth)
 *   2. Server replies: VER(0x05) | METHOD(0x00)
 *   3. Client sends CONNECT: VER(0x05) | CMD(0x01) | RSV(0x00) | ATYP | DST.ADDR | DST.PORT
 *   4. Server replies: VER(0x05) | REP | RSV(0x00) | ATYP | BND.ADDR | BND.PORT
 *
 * CRITICAL: On Android 11+ (API 30+), the process is bound to the physical
 * network via bindProcessToNetwork(). We must use ZeroTier's native socket
 * API (zts_socket/zts_connect) to create connections through the virtual
 * network, NOT regular Java sockets. Regular sockets would route through
 * the physical network (bypassing ZeroTier entirely).
 *
 * However, since our ZT socket API returns a regular file descriptor that
 * we can wrap in Java I/O streams, we use ZtEngine.ztsTcpConnect() for
 * the initial connection and then use the fd for data transfer.
 */
class ZtSocks5Client(
    private val vpnService: VpnService
) {
    companion object {
        private const val TAG = "ZtSocks5Client"

        // SOCKS5 protocol constants
        private const val SOCKS_VERSION = 0x05.toByte()
        private const val AUTH_NONE = 0x00.toByte()
        private const val AUTH_NO_ACCEPTABLE = 0xFF.toByte()
        private const val CMD_CONNECT = 0x01.toByte()
        private const val ATYP_IPV4 = 0x01.toByte()
        private const val ATYP_DOMAIN = 0x03.toByte()
        private const val ATYP_IPV6 = 0x04.toByte()
        private const val REPLY_SUCCESS = 0x00.toByte()
    }

    /**
     * Establish a SOCKS5 connection through the ZeroTier virtual network
     * to the target host:port via the Sender's SOCKS5 proxy.
     *
     * @param proxyAddress The Sender's ZeroTier virtual IP address
     * @param proxyPort The Sender's SOCKS5 proxy port (typically 1080)
     * @param targetHost The target host to connect to
     * @param targetPort The target port to connect to
     * @return Socks5Connection if successful, null on failure
     */
    suspend fun connectThroughProxy(
        proxyAddress: String,
        proxyPort: Int,
        targetHost: String,
        targetPort: Int
    ): Socks5Connection? = withContext(Dispatchers.IO) {
        try {
            // Step 1: Connect to the Sender's SOCKS5 proxy through ZeroTier
            val proxyFd = connectToZtProxy(proxyAddress, proxyPort)
            if (proxyFd < 0) {
                Log.e(TAG, "Failed to connect to SOCKS5 proxy at $proxyAddress:$proxyPort (fd=$proxyFd)")
                return@withContext null
            }

            Log.i(TAG, "Connected to SOCKS5 proxy at $proxyAddress:$proxyPort (fd=$proxyFd)")

            // Step 2: Perform SOCKS5 handshake
            // We need to get I/O streams for the ZT socket file descriptor
            // Since ztsTcpConnect returns a raw fd, we need to create a Socket from it
            // Unfortunately, Android doesn't provide a direct way to create a Socket from a raw fd
            // We'll use the native methods to read/write through the fd instead
            val handshakeOk = performSocks5Handshake(proxyFd, targetHost, targetPort)
            if (!handshakeOk) {
                Log.e(TAG, "SOCKS5 handshake failed for $targetHost:$targetPort")
                closeFd(proxyFd)
                return@withContext null
            }

            Log.i(TAG, "SOCKS5 CONNECT established: $targetHost:$targetPort via $proxyAddress:$proxyPort")

            return@withContext Socks5Connection(
                fd = proxyFd,
                proxyAddress = proxyAddress,
                proxyPort = proxyPort,
                targetHost = targetHost,
                targetPort = targetPort
            )

        } catch (e: Exception) {
            Log.e(TAG, "SOCKS5 connection failed: ${e.message}", e)
            null
        }
    }

    /**
     * Connect to the Sender's SOCKS5 proxy through the ZeroTier virtual network.
     * Uses ZtEngine.ztsTcpConnect() which creates a native ZT TCP socket.
     *
     * CRITICAL: On Android 11+, the process is bound to the physical network
     * via bindProcessToNetwork(). Regular Java sockets would bypass the ZT
     * virtual network entirely. We MUST use the ZT native socket API.
     */
    private fun connectToZtProxy(proxyAddress: String, proxyPort: Int): Int {
        return try {
            val fd = ZtEngine.ztsTcpConnect(proxyAddress, proxyPort)
            if (fd < 0) {
                Log.e(TAG, "ztsTcpConnect failed for $proxyAddress:$proxyPort (fd=$fd)")
            }
            fd
        } catch (e: Exception) {
            Log.e(TAG, "Exception in ztsTcpConnect: ${e.message}", e)
            -1
        }
    }

    /**
     * Perform the SOCKS5 handshake with the Sender's proxy.
     * Uses native read/write through the ZT socket file descriptor.
     */
    private suspend fun performSocks5Handshake(
        fd: Int,
        targetHost: String,
        targetPort: Int
    ): Boolean = withContext(Dispatchers.IO) {
        try {
            // ── Step 1: Method Selection ──────────────────────────────
            // Send: VER(1) | NMETHODS(1) | METHODS(1)
            val methodRequest = byteArrayOf(SOCKS_VERSION, 0x01, AUTH_NONE)
            val sent1 = nativeWrite(fd, methodRequest)
            if (sent1 < 0) {
                Log.e(TAG, "Failed to send SOCKS5 method selection")
                return@withContext false
            }

            // Receive: VER(1) | METHOD(1)
            val methodReply = ByteArray(2)
            val read1 = nativeRead(fd, methodReply)
            if (read1 < 2) {
                Log.e(TAG, "Failed to receive SOCKS5 method reply (read=$read1)")
                return@withContext false
            }

            if (methodReply[0] != SOCKS_VERSION || methodReply[1] == AUTH_NO_ACCEPTABLE) {
                Log.e(TAG, "SOCKS5 method negotiation failed: ver=${methodReply[0]} method=${methodReply[1]}")
                return@withContext false
            }

            // ── Step 2: CONNECT Request ───────────────────────────────
            // Build: VER(1) | CMD(1) | RSV(1) | ATYP(1) | DST.ADDR | DST.PORT(2)
            val connectRequest = buildConnectRequest(targetHost, targetPort)
            val sent2 = nativeWrite(fd, connectRequest)
            if (sent2 < 0) {
                Log.e(TAG, "Failed to send SOCKS5 CONNECT request")
                return@withContext false
            }

            // Receive: VER(1) | REP(1) | RSV(1) | ATYP(1) | BND.ADDR | BND.PORT(2)
            // Minimum: 10 bytes for IPv4 reply
            val connectReply = ByteArray(256)
            val read2 = nativeRead(fd, connectReply)
            if (read2 < 4) {
                Log.e(TAG, "Failed to receive SOCKS5 CONNECT reply (read=$read2)")
                return@withContext false
            }

            val replyCode = connectReply[1]
            if (replyCode != REPLY_SUCCESS) {
                val errorMsg = when (replyCode.toInt()) {
                    0x01 -> "General SOCKS server failure"
                    0x02 -> "Connection not allowed by ruleset"
                    0x03 -> "Network unreachable"
                    0x04 -> "Host unreachable"
                    0x05 -> "Connection refused"
                    0x06 -> "TTL expired"
                    0x07 -> "Command not supported"
                    0x08 -> "Address type not supported"
                    else -> "Unknown error code: $replyCode"
                }
                Log.e(TAG, "SOCKS5 CONNECT failed: $errorMsg")
                return@withContext false
            }

            return@withContext true

        } catch (e: Exception) {
            Log.e(TAG, "SOCKS5 handshake exception: ${e.message}", e)
            false
        }
    }

    /**
     * Build a SOCKS5 CONNECT request for the target host:port.
     */
    private fun buildConnectRequest(host: String, port: Int): ByteArray {
        // Try to parse as IPv4/IPv6 address first, fall back to domain name
        var addrBytes: ByteArray
        var atyp: Byte

        try {
            val inetAddr = InetAddress.getByName(host)
            addrBytes = inetAddr.address
            atyp = when (inetAddr) {
                is java.net.Inet6Address -> ATYP_IPV6
                else -> ATYP_IPV4
            }
        } catch (e: Exception) {
            // Use domain name addressing
            val domainBytes = host.toByteArray(Charsets.US_ASCII)
            addrBytes = byteArrayOf(domainBytes.size.toByte()) + domainBytes
            atyp = ATYP_DOMAIN
        }

        val request = byteArrayOf(
            SOCKS_VERSION, CMD_CONNECT, 0x00, atyp
        ) + addrBytes + byteArrayOf(
            (port shr 8).toByte(),
            port.toByte()
        )

        return request
    }

    /**
     * Write data to a native file descriptor.
     */
    private fun nativeWrite(fd: Int, data: ByteArray): Int {
        return ZtEngine.nativeSendToFd(fd, data, data.size)
    }

    /**
     * Read data from a native file descriptor.
     */
    private fun nativeRead(fd: Int, buffer: ByteArray): Int {
        return ZtEngine.nativeRecvFromFd(fd, buffer, buffer.size)
    }

    /**
     * Close a native file descriptor.
     */
    private fun closeFd(fd: Int) {
        ZtEngine.nativeCloseFd(fd)
    }

    /**
     * Represents an established SOCKS5 connection through the ZeroTier network.
     */
    data class Socks5Connection(
        val fd: Int,
        val proxyAddress: String,
        val proxyPort: Int,
        val targetHost: String,
        val targetPort: Int
    ) {
        /**
         * Write data to the SOCKS5 connection (towards the target via proxy).
         */
        fun write(data: ByteArray, length: Int = data.size): Int {
            return ZtEngine.nativeSendToFd(fd, data, length)
        }

        /**
         * Read data from the SOCKS5 connection (from the target via proxy).
         */
        fun read(buffer: ByteArray): Int {
            return ZtEngine.nativeRecvFromFd(fd, buffer, buffer.size)
        }

        /**
         * Close the SOCKS5 connection.
         */
        fun close() {
            ZtEngine.nativeCloseFd(fd)
        }
    }
}
