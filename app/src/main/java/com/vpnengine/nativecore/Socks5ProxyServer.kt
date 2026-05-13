package com.vpnengine.nativecore

import android.net.VpnService
import android.util.Log

/**
 * Socks5ProxyServer — Thin Kotlin wrapper around the native SOCKS5 server.
 *
 * The previous pure-Kotlin implementation used `java.net.ServerSocket` to
 * bind to the ZeroTier virtual IP, which CANNOT WORK: that IP exists only
 * inside libzt's user-space lwIP stack, not inside the Linux kernel, so
 * the kernel-level bind() either failed with EADDRNOTAVAIL or silently
 * bound to a useless local interface that never sees any traffic from
 * the ZT mesh.
 *
 * The real implementation now lives in C++ ([`Socks5Server.cpp`]) where it
 * binds with libzt's [`zts_socket`] / [`zts_bind`] / [`zts_listen`] /
 * [`zts_accept`] APIs against the ZeroTier user-space stack. Outgoing
 * connections to the real internet are made with regular BSD sockets that
 * are protected via [`VpnService.protect`] (through a JNI callback) so
 * they never re-enter this device's own VPN tunnel.
 */
class Socks5ProxyServer(
    private val bindAddress: String,
    private val bindPort: Int = DEFAULT_PORT,
    @Suppress("unused") private val vpnService: VpnService? = null,
) {
    companion object {
        private const val TAG = "Socks5Proxy"
        const val DEFAULT_PORT = 1080
    }

    @Volatile
    var isRunning = false
        private set

    /**
     * Start the native SOCKS5 server bound to the ZeroTier virtual IP via
     * libzt's user-space stack. Returns true if the listening socket was
     * created successfully.
     */
    fun start(): Boolean {
        if (isRunning) {
            Log.w(TAG, "Proxy already running on $bindAddress:$bindPort")
            return true
        }
        val ok = ZtEngine.startSocks5Safe(bindAddress, bindPort)
        if (!ok) {
            Log.e(
                TAG,
                "Failed to start native SOCKS5 on $bindAddress:$bindPort — ${ZtEngine.getSocks5ErrorSafe()}"
            )
            isRunning = false
            VpnStateHolder.updateSocks5ProxyRunning(false)
            return false
        }
        isRunning = true
        VpnStateHolder.updateSocks5ProxyRunning(true)
        Log.i(TAG, "Native SOCKS5 proxy started on ZT $bindAddress:$bindPort")
        return true
    }

    /** Stop the native SOCKS5 server. Idempotent. */
    fun stop() {
        if (!isRunning) return
        isRunning = false
        VpnStateHolder.updateSocks5ProxyRunning(false)
        ZtEngine.stopSocks5Safe()
        Log.i(TAG, "Native SOCKS5 proxy stopped")
    }
}
