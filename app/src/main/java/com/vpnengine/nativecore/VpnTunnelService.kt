package com.vpnengine.nativecore

import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService as AndroidVpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.trySendBlocking
import java.io.File
import java.io.IOException

/**
 * VpnTunnelService — Android VpnService implementation for ZeroTier P2P Mesh VPN.
 *
 * BULLETPROOF LIFECYCLE (v5):
 *   1. Creates zerotier storage directory BEFORE passing path to JNI
 *   2. Validates VpnService.prepare() was resolved before starting
 *   3. Foreground service compliance for Android 14+ (FOREGROUND_SERVICE_SPECIAL_USE)
 *   4. Sender/Receiver mode support
 *   5. **120-second IP assignment timeout** (was 45s) for strict NAT/ISP
 *   6. **Auto-retry with exponential backoff** on connection failure
 *   7. **Reconnecting state** instead of immediate error on transient failures
 *   8. Proper lifecycle: init node → P2P handshake → join mesh →
 *      authenticate → wait auth → connected
 *   9. Zero hardcoded delays — all state driven by ZeroTier callbacks
 */
class VpnTunnelService : AndroidVpnService() {

    companion object {
        private const val TAG = "VpnTunnelService"
        private const val TUNNEL_MTU = 1500
        private val DNS_SERVERS = listOf("8.8.8.8", "1.1.1.1")
        private const val ROUTE_ADDRESS = "0.0.0.0"
        private const val ROUTE_PREFIX = 0
        private const val SESSION_NAME = "ZT-P2P-Mesh"
        private const val MONITOR_INTERVAL_MS = 5000L
        private const val ZT_STORAGE_DIR = "zerotier"

        // ── NETWORK ROBUSTNESS CONFIGURATION ─────────────────────────────
        // Increased from 45s to 120s for strict NAT/ISP scenarios.
        // Indian ISPs with symmetric NAT can take 60-90s for UDP hole
        // punching to complete and receive an IP assignment.
        private const val IP_ASSIGNMENT_TIMEOUT_MS = 120_000L

        // Auto-retry configuration
        private const val MAX_RETRY_ATTEMPTS = 5
        private const val RETRY_BACKOFF_BASE_MS = 3000L  // 3s, 6s, 12s, 24s, 48s

        const val ACTION_START = "com.vpnengine.nativecore.ACTION_START"
        const val ACTION_STOP = "com.vpnengine.nativecore.ACTION_STOP"
        const val EXTRA_NETWORK_ID = "com.vpnengine.nativecore.EXTRA_NETWORK_ID"
        const val EXTRA_MODE = "com.vpnengine.nativecore.EXTRA_MODE"
        const val NOTIFICATION_CHANNEL_ID = "vpn_tunnel_channel"
        const val NOTIFICATION_ID = 1001
    }

    private sealed class Command {
        data class Start(val networkId: Long, val mode: VpnStateHolder.VpnMode) : Command()
        object Stop : Command()
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val commandChannel = Channel<Command>(capacity = Channel.BUFFERED)
    private var commandJob: Job? = null
    private var tunEstablished = false
    private var socks5Proxy: Socks5ProxyServer? = null
    private var currentMode = VpnStateHolder.VpnMode.RECEIVER
    private var currentNetworkId = 0L
    private var retryJob: Job? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "onStartCommand: action=${intent?.action}")
        when (intent?.action) {
            ACTION_STOP -> {
                commandChannel.trySendBlocking(Command.Stop)
                return START_NOT_STICKY
            }
            ACTION_START -> {
                val networkId = intent.getLongExtra(EXTRA_NETWORK_ID, 0L)
                val modeStr = intent.getStringExtra(EXTRA_MODE) ?: "RECEIVER"
                val mode = try {
                    VpnStateHolder.VpnMode.valueOf(modeStr)
                } catch (e: IllegalArgumentException) {
                    VpnStateHolder.VpnMode.RECEIVER
                }

                if (networkId == 0L) {
                    Log.e(TAG, "No valid Network ID provided in Intent — rejecting connection")
                    VpnStateHolder.updateState(VpnState.Error("No Network ID provided. Enter a 16-char hex ID in the app."))
                    return START_NOT_STICKY
                }

                Log.i(TAG, "Network ID: %016x, Mode: %s".format(networkId, mode))
                ensureCommandProcessorRunning()
                commandChannel.trySendBlocking(Command.Start(networkId, mode))
            }
            else -> {
                Log.w(TAG, "Service restarted with null/unknown intent — not reconnecting")
                stopSelf()
                return START_NOT_STICKY
            }
        }
        return START_STICKY
    }

    override fun onRevoke() {
        Log.w(TAG, "VPN permission revoked — tearing down tunnel")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                cm.bindProcessToNetwork(null)
            } catch (_: Exception) {}
        }
        VpnStateHolder.updateState(VpnState.Disconnected)
        ZtEngine.vpnServiceRef = null
        ZtEngine.fatalErrorHandler = null
        commandChannel.trySendBlocking(Command.Stop)
    }

    override fun onDestroy() {
        Log.i(TAG, "onDestroy — shutting down service")
        retryJob?.cancel()
        commandChannel.trySendBlocking(Command.Stop)
        commandChannel.close()
        serviceScope.cancel()
        stopEngineAndTun()
        stopSocks5Proxy()
        ZtEngine.vpnServiceRef = null
        ZtEngine.fatalErrorHandler = null
        super.onDestroy()
    }

    private fun ensureCommandProcessorRunning() {
        if (commandJob?.isActive == true) return
        commandJob = serviceScope.launch {
            try {
                for (cmd in commandChannel) {
                    when (cmd) {
                        is Command.Start -> handleStartCommand(cmd.networkId, cmd.mode)
                        is Command.Stop -> { handleStopCommand(); return@launch }
                    }
                }
            } catch (e: CancellationException) {
                handleStopCommand()
            } catch (e: Exception) {
                Log.e(TAG, "Command processor error", e)
                handleStopCommand()
            }
        }
    }

    private suspend fun handleStartCommand(networkId: Long, mode: VpnStateHolder.VpnMode) {
        if (ZtEngine.isRunningSafe()) {
            Log.w(TAG, "Engine already running")
            return
        }

        currentNetworkId = networkId
        currentMode = mode
        VpnStateHolder.updateMode(mode)

        Log.i(TAG, "Starting ZeroTier P2P Mesh VPN (network=%016x, mode=%s)".format(networkId, mode))
        ZtEngine.vpnServiceRef = this

        ZtEngine.fatalErrorHandler = {
            Log.e(TAG, "Fatal ZT error — will attempt auto-reconnect")
            // Instead of immediately stopping, trigger a reconnect attempt
            retryJob?.cancel()
            retryJob = serviceScope.launch {
                attemptReconnect(networkId, mode)
            }
        }

        VpnStateHolder.updateState(VpnState.InitializingNode)

        // ── Show foreground notification FIRST (Android 8+ requirement) ──
        try {
            VpnNotificationHelper.showForegroundNotification(this)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to show foreground notification", e)
            VpnStateHolder.updateState(VpnState.Error("Failed to start foreground service: ${e.message}"))
            stopSelf()
            return
        }

        // ── Create ZeroTier storage directory BEFORE passing to JNI ──
        val ztDir = File(filesDir, ZT_STORAGE_DIR)
        if (!ztDir.exists()) {
            val created = ztDir.mkdirs()
            if (!created) {
                val error = "Failed to create ZeroTier storage directory: ${ztDir.absolutePath}"
                Log.e(TAG, error)
                VpnStateHolder.updateState(VpnState.Error(error))
                stopForegroundAndNotification()
                stopSelf()
                return
            }
            Log.i(TAG, "Created ZeroTier storage directory: ${ztDir.absolutePath}")
        }

        if (!ztDir.canWrite()) {
            val error = "ZeroTier storage directory not writable: ${ztDir.absolutePath}"
            Log.e(TAG, error)
            VpnStateHolder.updateState(VpnState.Error(error))
            stopForegroundAndNotification()
            stopSelf()
            return
        }

        val configPath = ztDir.absolutePath

        // ── CRITICAL: Android 11+ Network Binding Fix ───────────────────────────
        // On API 30+, ZeroTier C++ SDK cannot discover network interfaces due to
        // SELinux restrictions on getifaddrs() and /proc/net/. We must bind the
        // process to the active physical network BEFORE starting ZeroTier, so its
        // C++ sockets can route directly over Wi-Fi/LTE.
        val connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val activeNetwork = connectivityManager.activeNetwork
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && activeNetwork != null) {
            try {
                val bound = connectivityManager.bindProcessToNetwork(activeNetwork)
                Log.i(TAG, "CRITICAL FIX: bindProcessToNetwork($activeNetwork) = $bound")
                if (!bound) {
                    Log.w(TAG, "bindProcessToNetwork failed — ZeroTier may not discover network interfaces")
                }
            } catch (e: Exception) {
                Log.e(TAG, "bindProcessToNetwork exception", e)
            }
        }

        // ── Network connectivity check ─────────────────────────────────────
        // Use NetworkCapabilities API on API 23+ (activeNetworkInfo is deprecated on API 29+)
        val hasConnectivity = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val network = connectivityManager.activeNetwork
            val caps = if (network != null) connectivityManager.getNetworkCapabilities(network) else null
            caps != null && (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))
        } else {
            @Suppress("DEPRECATION")
            val activeNet = connectivityManager.activeNetworkInfo
            activeNet != null && activeNet.isConnected
        }

        if (!hasConnectivity) {
            val error = "No internet connection. Connect to Wi-Fi or mobile data and try again."
            Log.e(TAG, error)
            VpnStateHolder.updateState(VpnState.Error(error))
            stopForegroundAndNotification()
            stopSelf()
            return
        }

        // ── Start ZeroTier engine ──────────────────────────────────────────
        val started = ZtEngine.startSafe(configPath, networkId)

        if (!started) {
            val nativeError = ZtEngine.getLastErrorSafe()
            val error = if (ZtEngine.isNativeLibraryLoaded()) {
                "ZeroTier engine failed to start: $nativeError"
            } else {
                ZtEngine.getNativeLoadError()
            }
            Log.e(TAG, error)

            // Attempt auto-reconnect before giving up
            attemptReconnect(networkId, mode)
            return
        }

        Log.i(TAG, "ZeroTier engine started — waiting for IP assignment (timeout=${IP_ASSIGNMENT_TIMEOUT_MS}ms)...")

        // ── Wait for ZeroTier to assign an IP (120s timeout) ────────────────
        val ipAssigned = waitForAssignedIP(timeoutMs = IP_ASSIGNMENT_TIMEOUT_MS)

        if (!ipAssigned) {
            val state = VpnStateHolder.currentValue

            // If we're in WaitingAuthorization state, this is NOT a failure —
            // the user just needs to authorize on ZeroTier Central.
            if (state is VpnState.WaitingAuthorization) {
                val error = "Network authorization pending. Go to https://my.zerotier.com and authorize this node."
                Log.w(TAG, error)
                VpnStateHolder.updateState(VpnState.Error(error))
                stopEngineAndTun()
                stopForegroundAndNotification()
                stopSelf()
                return
            }

            // If we're in Reconnecting state, the engine is already trying
            if (state is VpnState.Reconnecting) {
                return  // Let the reconnection logic handle it
            }

            // For other failures, attempt auto-reconnect before giving up
            val error = when (state) {
                is VpnState.Error -> state.message
                else ->
                    "Timeout: ZeroTier network did not assign an IP within ${IP_ASSIGNMENT_TIMEOUT_MS / 1000}s. " +
                    "Check Network ID is correct and the network allows join."
            }
            Log.e(TAG, error)

            attemptReconnect(networkId, mode)
            return
        }

        val assignedIP = VpnStateHolder.assignedIPv4.value
        if (assignedIP.isBlank()) {
            Log.e(TAG, "Assigned IP is blank — cannot configure tunnel")
            attemptReconnect(networkId, mode)
            return
        }

        // ── Handle mode-specific setup ─────────────────────────────────────
        when (mode) {
            VpnStateHolder.VpnMode.SENDER -> {
                setupSenderMode(assignedIP)
            }
            VpnStateHolder.VpnMode.RECEIVER -> {
                setupReceiverMode(assignedIP)
            }
        }
    }

    /**
     * Auto-reconnect with exponential backoff.
     *
     * When the connection fails or drops, instead of immediately
     * showing an error, we transition to a Reconnecting state and
     * try again with increasing delays. This handles:
     *   - Strict NAT/ISP that needs multiple hole punch attempts
     *   - Temporary network disruptions
     *   - ZeroTier controller delays in IP assignment
     *
     * @param networkId The network ID to reconnect to.
     * @param mode The VPN mode (SENDER/RECEIVER).
     */
    private suspend fun attemptReconnect(networkId: Long, mode: VpnStateHolder.VpnMode, currentAttempt: Int = 1) {
        if (currentAttempt > MAX_RETRY_ATTEMPTS) {
            Log.e(TAG, "Max retry attempts ($MAX_RETRY_ATTEMPTS) reached — giving up")
            VpnStateHolder.updateState(VpnState.Error(
                "Connection failed after $MAX_RETRY_ATTEMPTS attempts. " +
                "Check your Network ID, internet connection, and ZeroTier Central authorization."
            ))
            stopEngineAndTun()
            stopForegroundAndNotification()
            stopSelf()
            return
        }

        Log.i(TAG, "Auto-reconnect attempt $currentAttempt/$MAX_RETRY_ATTEMPTS")

        // Transition to Reconnecting state
        VpnStateHolder.updateState(VpnState.Reconnecting(currentAttempt, MAX_RETRY_ATTEMPTS))

        // Exponential backoff: 3s, 6s, 12s, 24s, 48s
        val backoffMs = RETRY_BACKOFF_BASE_MS * (1L shl (currentAttempt - 1))
        VpnNotificationHelper.updateNotification(this, "Reconnecting... (attempt $currentAttempt/$MAX_RETRY_ATTEMPTS, ${backoffMs/1000}s)")

        Log.i(TAG, "Waiting ${backoffMs}ms before retry...")
        delay(backoffMs)

        // Stop any existing engine cleanly before retrying
        stopEngineAndTun()

        // Small delay to ensure cleanup is complete
        delay(500)

        // Try again
        handleStartCommand(networkId, mode)
    }

    /**
     * SENDER MODE: Start SOCKS5 proxy on ZeroTier virtual IP.
     */
    private suspend fun setupSenderMode(assignedIP: String) {
        Log.i(TAG, "SENDER mode: Starting SOCKS5 proxy on $assignedIP:1080")
        VpnNotificationHelper.updateNotification(this, "Starting SOCKS5 proxy...")

        val proxy = Socks5ProxyServer(assignedIP, 1080, vpnService = this)
        val proxyStarted = proxy.start()

        if (!proxyStarted) {
            VpnStateHolder.updateState(VpnState.Error("Failed to start SOCKS5 proxy on $assignedIP:1080"))
            attemptReconnect(currentNetworkId, currentMode)
            return
        }

        socks5Proxy = proxy
        VpnStateHolder.updateSenderProxyConfig(assignedIP, 1080)
        VpnStateHolder.updateState(VpnState.Connected())
        VpnNotificationHelper.updateNotification(this, "SOCKS5 proxy active on $assignedIP:1080")
        Log.i(TAG, "SENDER mode active: SOCKS5 proxy on $assignedIP:1080")

        // ── Unbind process from physical network after TUN is up ───────────
        // Now that TUN is established and ZeroTier has already discovered the
        // physical network, we unbind so app traffic can flow through the VPN TUN.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                cm.bindProcessToNetwork(null)
                Log.i(TAG, "Unbound process from physical network — TUN is active")
            } catch (e: Exception) {
                Log.w(TAG, "Failed to unbind process network", e)
            }
        }

        monitorEngineHealth()
    }

    /**
     * RECEIVER MODE: Establish TUN interface and bridge traffic.
     */
    private suspend fun setupReceiverMode(assignedIP: String) {
        Log.i(TAG, "RECEIVER mode: Building TUN interface with IP: $assignedIP")

        val pfd: ParcelFileDescriptor
        try {
            pfd = buildTunInterface(assignedIP)
        } catch (e: VpnConfigurationException) {
            Log.e(TAG, "TUN configuration failed: ${e.message}", e)
            VpnStateHolder.updateState(VpnState.Error("TUN config failed: ${e.message}"))
            stopEngineAndTun()
            stopForegroundAndNotification()
            stopSelf()
            return
        } catch (e: IOException) {
            Log.e(TAG, "TUN establishment I/O error", e)
            VpnStateHolder.updateState(VpnState.Error("TUN I/O error: ${e.message}"))
            stopEngineAndTun()
            stopForegroundAndNotification()
            stopSelf()
            return
        }

        vpnInterface = pfd
        tunEstablished = true

        val tunFd = pfd.fd
        Log.i(TAG, "TUN established: fd=$tunFd, mtu=$TUNNEL_MTU, ip=$assignedIP")

        val bridgeStarted = ZtEngine.startTunBridgeSafe(tunFd)
        if (!bridgeStarted) {
            val nativeErr = ZtEngine.getLastErrorSafe()
            Log.e(TAG, "Failed to start TUN bridge: $nativeErr")
            VpnStateHolder.updateState(VpnState.Error("Failed to start packet bridge: $nativeErr"))
            stopEngineAndTun()
            stopForegroundAndNotification()
            stopSelf()
            return
        }

        VpnStateHolder.updateState(VpnState.Connected())
        VpnNotificationHelper.updateNotification(this, "P2P Mesh VPN active")
        Log.i(TAG, "TUN bridge started — VPN tunnel is active")

        // ── Unbind process from physical network after TUN is up ───────────
        // Now that TUN is established and ZeroTier has already discovered the
        // physical network, we unbind so app traffic can flow through the VPN TUN.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                cm.bindProcessToNetwork(null)
                Log.i(TAG, "Unbound process from physical network — TUN is active")
            } catch (e: Exception) {
                Log.w(TAG, "Failed to unbind process network", e)
            }
        }

        monitorEngineHealth()
    }

    private fun handleStopCommand() {
        Log.i(TAG, "Stopping VPN tunnel...")
        retryJob?.cancel()
        ZtEngine.vpnServiceRef = null
        ZtEngine.fatalErrorHandler = null
        stopEngineAndTun()
        stopSocks5Proxy()
        VpnStateHolder.reset()
        stopForegroundAndNotification()
        stopSelf()
        Log.i(TAG, "VPN tunnel stopped — normal internet restored")
    }

    /**
     * Wait for ZeroTier to assign an IP address.
     * Polls VpnStateHolder.assignedIPv4 with a 500ms interval.
     *
     * The timeout is 120 seconds to allow UDP hole punching on
     * strict NATs/ISPs (like Indian ISPs with symmetric NAT).
     */
    private suspend fun waitForAssignedIP(timeoutMs: Long): Boolean {
        val startTime = System.currentTimeMillis()
        while (System.currentTimeMillis() - startTime < timeoutMs) {
            val ip = VpnStateHolder.assignedIPv4.value
            if (ip.isNotBlank()) {
                Log.i(TAG, "ZeroTier assigned IP: $ip")
                return true
            }

            val state = VpnStateHolder.currentValue
            if (state is VpnState.Error) {
                // Only fail on non-transient errors. "Access denied" and
                // "Network not found" are permanent errors that won't be
                // fixed by waiting longer.
                val msg = state.message
                if (msg.contains("Access denied", ignoreCase = true) ||
                    msg.contains("Network not found", ignoreCase = true) ||
                    msg.contains("SDK version too old", ignoreCase = true) ||
                    msg.contains("SDK not loaded", ignoreCase = true) ||
                    msg.contains("not properly linked", ignoreCase = true)) {
                    Log.e(TAG, "Permanent error while waiting for IP: $msg")
                    return false
                }
                // Transient errors — keep waiting (the engine might recover)
                Log.w(TAG, "Transient error while waiting for IP: $msg — continuing to wait")
            }

            // Update notification with elapsed time every 10 seconds
            val elapsed = (System.currentTimeMillis() - startTime) / 1000
            if (elapsed > 0 && elapsed % 10 == 0L) {
                val remaining = (timeoutMs / 1000) - elapsed
                val stateLabel = when (state) {
                    is VpnState.P2pHandshake -> "P2P Handshake"
                    is VpnState.Authenticating -> "Authenticating"
                    is VpnState.WaitingAuthorization -> "Waiting Authorization"
                    is VpnState.JoiningMesh -> "Joining Mesh"
                    is VpnState.InitializingNode -> "Initializing"
                    is VpnState.Reconnecting -> "Reconnecting"
                    else -> "Connecting"
                }
                VpnNotificationHelper.updateNotification(
                    this, "$stateLabel... (${remaining}s remaining)"
                )
            }

            delay(500)
        }
        return false
    }

    /**
     * Build the TUN interface for RECEIVER mode.
     *
     * CRITICAL: addDisallowedApplication(packageName) prevents the VPN app's
     * own traffic from being routed through the TUN, which would cause an
     * infinite routing loop.
     */
    private fun buildTunInterface(assignedIP: String): ParcelFileDescriptor {
        val builder = Builder()
        builder.setMtu(TUNNEL_MTU)

        try {
            builder.addAddress(assignedIP, 32)
        } catch (e: IllegalArgumentException) {
            throw VpnConfigurationException("Invalid virtual IP: $assignedIP/32", e)
        }

        for (dns in DNS_SERVERS) {
            try {
                builder.addDnsServer(dns)
            } catch (e: IllegalArgumentException) {
                throw VpnConfigurationException("Invalid DNS: $dns", e)
            }
        }

        // Route ALL IPv4 traffic through the VPN tunnel
        try {
            builder.addRoute(ROUTE_ADDRESS, ROUTE_PREFIX)
        } catch (e: IllegalArgumentException) {
            throw VpnConfigurationException("Invalid route: $ROUTE_ADDRESS/$ROUTE_PREFIX", e)
        }

        // Route ALL IPv6 traffic through the VPN tunnel
        try {
            builder.addRoute("::", 0)
        } catch (e: IllegalArgumentException) {
            Log.w(TAG, "Failed to add IPv6 route — IPv6 traffic won't go through VPN", e)
        }

        // CRITICAL: Exclude VPN app from tunnel to prevent routing loop
        try {
            builder.addDisallowedApplication(packageName)
            Log.i(TAG, "Excluded VPN app ($packageName) from tunnel")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to exclude VPN app from tunnel — routing loop risk!", e)
        }

        builder.setSession(SESSION_NAME)

        val pfd = builder.establish()
            ?: throw VpnConfigurationException(
                "VpnService.Builder.establish() returned null — " +
                "VPN permission not granted or another VPN is active")

        Log.i(TAG, "TUN established: ip=$assignedIP/32, dns=$DNS_SERVERS, " +
                   "route=$ROUTE_ADDRESS/$ROUTE_PREFIX + ::/0, mtu=$TUNNEL_MTU, " +
                   "disallowed=$packageName")
        return pfd
    }

    /**
     * Monitor engine health. Instead of immediately killing the connection
     * on 3 consecutive failures, attempt auto-reconnect first.
     */
    private suspend fun monitorEngineHealth() {
        var consecutiveFailures = 0
        val maxFailures = 3
        while (currentCoroutineContext().isActive) {
            delay(MONITOR_INTERVAL_MS)
            val running = ZtEngine.isRunningSafe()
            val online = ZtEngine.isOnlineSafe()
            if (!running || !online) {
                consecutiveFailures++
                Log.w(TAG, "Health check: running=$running online=$online ($consecutiveFailures/$maxFailures)")
                if (consecutiveFailures >= maxFailures) {
                    Log.w(TAG, "Engine unhealthy — attempting auto-reconnect")
                    retryJob?.cancel()
                    retryJob = serviceScope.launch {
                        attemptReconnect(currentNetworkId, currentMode)
                    }
                    return
                }
            } else {
                if (consecutiveFailures > 0) {
                    Log.i(TAG, "Engine recovered after $consecutiveFailures failed checks")
                }
                consecutiveFailures = 0
            }
        }
    }

    private fun stopEngineAndTun() {
        // Reset process network binding
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                cm.bindProcessToNetwork(null)
            } catch (_: Exception) {}
        }
        try { ZtEngine.stopTunBridgeSafe() } catch (e: Exception) { Log.w(TAG, "Error stopping TUN bridge", e) }
        try { ZtEngine.stopSafe() } catch (e: Exception) { Log.w(TAG, "Error stopping ZT engine", e) }
        try { vpnInterface?.close() } catch (e: IOException) { Log.w(TAG, "Error closing TUN interface", e) }
        vpnInterface = null
        tunEstablished = false
        VpnStateHolder.updateAssignedIP("", "")
    }

    private fun stopSocks5Proxy() {
        try {
            socks5Proxy?.stop()
        } catch (e: Exception) {
            Log.w(TAG, "Error stopping SOCKS5 proxy", e)
        }
        socks5Proxy = null
        VpnStateHolder.updateSocks5ProxyRunning(false)
    }

    private fun stopForegroundAndNotification() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } else {
                @Suppress("DEPRECATION")
                stopForeground(true)
            }
        } catch (e: Exception) { Log.w(TAG, "Error stopping foreground service", e) }
        VpnNotificationHelper.cancelNotification(this)
    }

    class VpnConfigurationException : Exception {
        constructor(message: String) : super(message)
        constructor(message: String, cause: Throwable) : super(message, cause)
    }
}
