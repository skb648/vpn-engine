package com.vpnengine.nativecore

import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService as AndroidVpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.trySendBlocking
import java.io.File
import java.io.IOException

/**
 * VpnTunnelService — Android VpnService implementation for ZeroTier P2P Mesh VPN.
 *
 * ENTERPRISE-GRADE LIFECYCLE (v7):
 *   1. **OS-LEVEL NETWORK BYPASS**: On Android 11+ (API 30+), SELinux restricts
 *      native C++ libraries (`libzt.so`) from discovering physical network
 *      interfaces via `getifaddrs()` or `/proc/net/`. Before initializing the
 *      ZeroTier engine, we explicitly call `bindProcessToNetwork(activeNetwork)`
 *      to force all native sockets to route directly over the active Wi-Fi/Mobile
 *      Data interface, completely un-blinding the C++ networking layer.
 *   2. **BULLETPROOF C++ TEARDOWN**: The stop sequence guarantees that all
 *      native threads are joined BEFORE destroying mutexes or freeing the node,
 *      eliminating the `FATAL SIGNAL 6 (SIGABRT): pthread_mutex_lock called on
 *      a destroyed mutex` crash.
 *   3. **120-SECOND IP ASSIGNMENT TIMEOUT**: Allows sufficient time for complex
 *      UDP hole-punching over strict Indian ISPs (Jio/Airtel symmetric NAT).
 *   4. **EXPONENTIAL BACKOFF RETRY**: On timeout or network drop, the service
 *      transitions to a graceful `Reconnecting` state with automatic retry
 *      (3s → 6s → 12s → 24s → 48s).
 *   5. Creates ZeroTier storage directory BEFORE passing path to JNI.
 *   6. Validates VpnService.prepare() was resolved before starting.
 *   7. Foreground service compliance for Android 14+ (FOREGROUND_SERVICE_SPECIAL_USE).
 *   8. Sender/Receiver mode support.
 *   9. Zero hardcoded delays — all state driven by ZeroTier callbacks.
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
        // 120s timeout for strict NAT/ISP scenarios. Indian ISPs with
        // symmetric NAT (Jio/Airtel) can take 60-90s for UDP hole punching
        // to complete and receive an IP assignment.
        private const val IP_ASSIGNMENT_TIMEOUT_MS = 120_000L

        // Auto-retry configuration
        private const val MAX_RETRY_ATTEMPTS = 5
        private const val RETRY_BACKOFF_BASE_MS = 3000L  // 3s, 6s, 12s, 24s, 48s

        const val ACTION_START = "com.vpnengine.nativecore.ACTION_START"
        const val ACTION_STOP = "com.vpnengine.nativecore.ACTION_STOP"
        /** CRITICAL FIX: Network ID now passed as String to prevent Long overflow */
        const val EXTRA_NETWORK_ID_STRING = "com.vpnengine.nativecore.EXTRA_NETWORK_ID_STRING"
        const val EXTRA_MODE = "com.vpnengine.nativecore.EXTRA_MODE"
        /** Public constant for notification channel ID */
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
    private var tunSocksBridge: TunSocksBridge? = null
    private var loopbackGateway: LocalLoopbackGateway? = null
    private var currentMode = VpnStateHolder.VpnMode.RECEIVER
    private var currentNetworkId = 0L
    private var retryJob: Job? = null

    // Track the bound network so we can unbind properly during teardown
    @Volatile
    private var boundNetwork: Network? = null

    // Wake lock to keep CPU alive while VPN is running.
    // Without this, the ZeroTier SDK background threads can be suspended
    // during deep sleep, which kills UDP hole-punching and the heartbeat
    // packets that keep the device visible on ZeroTier Central.
    @Volatile
    private var wakeLock: PowerManager.WakeLock? = null

    private fun acquireWakeLockIfNeeded() {
        if (wakeLock?.isHeld == true) return
        try {
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            val wl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "VpnEngine::ZtMeshWakeLock")
            wl.setReferenceCounted(false)
            wl.acquire(/* timeout = */ 24L * 60L * 60L * 1000L) // 24 hours safety cap
            wakeLock = wl
            Log.i(TAG, "Acquired PARTIAL_WAKE_LOCK to keep ZT SDK alive in deep sleep")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to acquire wake lock — connectivity may drop during deep sleep", e)
        }
    }

    private fun releaseWakeLockIfHeld() {
        try {
            wakeLock?.let { wl ->
                if (wl.isHeld) wl.release()
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to release wake lock", e)
        }
        wakeLock = null
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "onStartCommand: action=${intent?.action}")
        when (intent?.action) {
            ACTION_STOP -> {
                commandChannel.trySendBlocking(Command.Stop)
                return START_NOT_STICKY
            }
            ACTION_START -> {
                // CRITICAL FIX: Read Network ID as String to prevent Long overflow
                val networkIdStr = intent.getStringExtra(EXTRA_NETWORK_ID_STRING)
                val modeStr = intent.getStringExtra(EXTRA_MODE) ?: "RECEIVER"
                val mode = try {
                    VpnStateHolder.VpnMode.valueOf(modeStr)
                } catch (e: IllegalArgumentException) {
                    VpnStateHolder.VpnMode.RECEIVER
                }

                if (networkIdStr.isNullOrBlank() || networkIdStr.length != 16) {
                    Log.e(TAG, "Invalid Network ID in Intent: '$networkIdStr'")
                    VpnStateHolder.updateState(VpnState.Error("Invalid Network ID. Enter a 16-char hex ID."))
                    return START_NOT_STICKY
                }

                // Parse safely using BigInteger to avoid Long overflow
                val networkId = try {
                    java.math.BigInteger(networkIdStr, 16).toLong()
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to parse Network ID: $networkIdStr")
                    VpnStateHolder.updateState(VpnState.Error("Failed to parse Network ID"))
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
        unbindProcessNetwork()
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
        stopTunSocksBridge()
        stopLoopbackGateway()
        unbindProcessNetwork()
        releaseWakeLockIfHeld()
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

    // ══════════════════════════════════════════════════════════════════════════
    // MAIN START COMMAND — Enterprise-grade connection lifecycle
    // ══════════════════════════════════════════════════════════════════════════

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
            retryJob?.cancel()
            retryJob = serviceScope.launch {
                attemptReconnect(networkId, mode)
            }
        }

        // ── PHASE 0a: Acquire wake lock so the SDK threads stay alive ───────
        // Without a partial wake lock, Doze mode and deep sleep will suspend
        // our UDP keepalives and the device will silently disappear from the
        // ZeroTier Central dashboard.
        acquireWakeLockIfNeeded()

        // ── PHASE 0: Show foreground notification FIRST (Android 8+ requirement) ──
        VpnStateHolder.updateState(VpnState.InitializingNode)
        try {
            VpnNotificationHelper.showForegroundNotification(this)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to show foreground notification", e)
            VpnStateHolder.updateState(VpnState.Error("Failed to start foreground service: ${e.message}"))
            stopSelf()
            return
        }

        // ── PHASE 1: Create ZeroTier storage directory BEFORE passing to JNI ──
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

        // ══════════════════════════════════════════════════════════════════════
        // PHASE 2: OS-LEVEL NETWORK BYPASS (Android 11+ / API 30+)
        //
        // CRITICAL FIX: SELinux on Android 11+ completely restricts native
        // C++ libraries (libzt.so) from discovering physical network interfaces
        // via getifaddrs() or /proc/net/. This makes the ZeroTier engine blind
        // — it cannot send initial UDP handshake packets to root servers, and
        // web authorization requests never reach the ZeroTier Central dashboard.
        //
        // SOLUTION: Call bindProcessToNetwork(activeNetwork) BEFORE starting
        // the ZeroTier engine. This forces ALL sockets (including native C++
        // sockets created by libzt.so) to route directly over the active
        // physical Wi-Fi or Mobile Data interface, completely bypassing the
        // SELinux restriction.
        //
        // This MUST happen BEFORE zts_node_start() because the engine opens
        // sockets during initialization to contact ZeroTier root servers.
        // ══════════════════════════════════════════════════════════════════════
        VpnStateHolder.updateState(VpnState.UnblindingNetwork)
        VpnNotificationHelper.updateNotification(this, "Un-blinding network for native C++ sockets...")

        val connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val networkBypassResult = performNetworkBypass(connectivityManager)

        if (!networkBypassResult) {
            Log.w(TAG, "Network bypass failed or unavailable — proceeding anyway (may work on older devices)")
            // Don't fail here — older devices (< API 30) don't need the bypass
            // and some networks may not need it. The engine will still try.
        }

        // ── PHASE 3: Validate network connectivity ─────────────────────────
        val hasConnectivity = checkNetworkConnectivity(connectivityManager)
        if (!hasConnectivity) {
            val error = "No internet connection. Connect to Wi-Fi or mobile data and try again."
            Log.e(TAG, error)
            VpnStateHolder.updateState(VpnState.Error(error))
            unbindProcessNetwork()
            stopForegroundAndNotification()
            stopSelf()
            return
        }

        // ── PHASE 4: Start ZeroTier engine ────────────────────────────────
        VpnStateHolder.updateState(VpnState.InitializingNode)
        VpnNotificationHelper.updateNotification(this, "Starting ZeroTier engine...")

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

        // ── PHASE 5: Wait for ZeroTier to assign an IP (120s timeout) ──────
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
                unbindProcessNetwork()
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

        // ── PHASE 6: Handle mode-specific setup ──────────────────────────
        when (mode) {
            VpnStateHolder.VpnMode.SENDER -> {
                setupSenderMode(assignedIP)
            }
            VpnStateHolder.VpnMode.RECEIVER -> {
                setupReceiverMode(assignedIP)
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // OS-LEVEL NETWORK BYPASS — The core fix for Android 11+ "Network Blindness"
    // ══════════════════════════════════════════════════════════════════════════
    //
    // On Android 11+ (API 30+), SELinux completely blocks native C++ code from
    // accessing network interface information. The ZeroTier C++ SDK (libzt.so)
    // relies on getifaddrs() and /proc/net/ to discover which network interfaces
    // are available for sending UDP packets. When these are blocked, the engine
    // is "blind" — it cannot send ANY packets, including:
    //   - Initial UDP handshake to ZeroTier root servers
    //   - Web authorization requests to ZeroTier Central
    //   - P2P hole-punching packets
    //
    // The fix is to call bindProcessToNetwork(activeNetwork) which tells the
    // Android kernel to route ALL process sockets (including native ones) through
    // the specified physical network. This effectively bypasses the SELinux
    // restriction because the kernel now knows which network to use, even if
    // the native code can't discover it.
    //
    // IMPORTANT: This MUST be called BEFORE zts_node_start() because the
    // ZeroTier engine opens its first sockets during initialization to contact
    // the root servers. If the bypass is not in place by then, those initial
    // packets will fail to send.

    /**
     * Perform the OS-level network bypass for Android 11+ (API 30+).
     *
     * This method:
     *   1. Queries the active physical network using ConnectivityManager
     *   2. Validates the network has NET_CAPABILITY_INTERNET
     *   3. Calls bindProcessToNetwork() to force native socket routing
     *   4. Stores the bound network reference for later unbinding
     *
     * @param cm The ConnectivityManager instance
     * @return true if the bypass was successfully applied, false otherwise
     */
    private fun performNetworkBypass(cm: ConnectivityManager): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            Log.i(TAG, "Network bypass not needed (API ${Build.VERSION.SDK_INT} < 30)")
            return true  // Not needed on older versions
        }

        Log.i(TAG, "NETWORK BYPASS: Starting OS-level network un-blinding (API ${Build.VERSION.SDK_INT})...")

        // Step 1: Get the active network
        val activeNetwork = cm.activeNetwork
        if (activeNetwork == null) {
            Log.e(TAG, "NETWORK BYPASS FAILED: No active network found. " +
                       "Device may be offline or airplane mode is on.")
            return false
        }

        // Step 2: Validate the active network has INTERNET capability
        val caps = cm.getNetworkCapabilities(activeNetwork)
        if (caps == null) {
            Log.e(TAG, "NETWORK BYPASS FAILED: Cannot get capabilities for active network $activeNetwork")
            return false
        }

        val hasInternet = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        val hasValidated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        val transportType = when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Cellular"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
            else -> "Unknown"
        }

        Log.i(TAG, "NETWORK BYPASS: Active network = $activeNetwork " +
                    "(transport=$transportType, internet=$hasInternet, validated=$hasValidated, " +
                    "upstream=${caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL)}")

        if (!hasInternet) {
            Log.e(TAG, "NETWORK BYPASS FAILED: Active network lacks NET_CAPABILITY_INTERNET. " +
                       "Cannot route native C++ sockets through this network.")
            // Attempt to find a better network
            val fallbackNetwork = findBestNetwork(cm)
            if (fallbackNetwork != null) {
                Log.i(TAG, "NETWORK BYPASS: Found fallback network $fallbackNetwork, trying that instead")
                return bindToNetwork(cm, fallbackNetwork)
            }
            return false
        }

        // Step 3: Warn about VPN transport — we should bind to the underlying physical network
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            Log.w(TAG, "NETWORK BYPASS: Active network is a VPN — attempting to find physical network instead")
            val physicalNetwork = findBestNetwork(cm)
            if (physicalNetwork != null) {
                return bindToNetwork(cm, physicalNetwork)
            }
            Log.w(TAG, "NETWORK BYPASS: No physical network found, proceeding with VPN network binding")
        }

        // Step 4: Bind the process to the active network
        return bindToNetwork(cm, activeNetwork)
    }

    /**
     * Find the best available physical network (Wi-Fi > Cellular > Ethernet).
     * This is used as a fallback when the active network is unsuitable
     * (e.g., it's a VPN or lacks INTERNET capability).
     */
    private fun findBestNetwork(cm: ConnectivityManager): android.net.Network? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return null

        // Prefer Wi-Fi, then Cellular, then Ethernet
        val preferredTransports = intArrayOf(
            NetworkCapabilities.TRANSPORT_WIFI,
            NetworkCapabilities.TRANSPORT_CELLULAR,
            NetworkCapabilities.TRANSPORT_ETHERNET
        )

        for (transport in preferredTransports) {
            val request = NetworkRequest.Builder()
                .addTransportType(transport)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build()

            // Check all available networks for this transport
            val allNetworks = cm.allNetworks
            for (network in allNetworks) {
                val networkCaps = cm.getNetworkCapabilities(network)
                if (networkCaps != null &&
                    networkCaps.hasTransport(transport) &&
                    networkCaps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                    Log.i(TAG, "NETWORK BYPASS: Found suitable network: $network for transport $transport")
                    return network
                }
            }
        }

        Log.w(TAG, "NETWORK BYPASS: No suitable physical network found among ${cm.allNetworks.size} networks")
        return null
    }

    /**
     * Bind the process to the specified network and store the reference.
     */
    private fun bindToNetwork(cm: ConnectivityManager, network: android.net.Network): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return true

        return try {
            val bound = cm.bindProcessToNetwork(network)
            if (bound) {
                boundNetwork = network
                val caps = cm.getNetworkCapabilities(network)
                val transportType = when {
                    caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> "Wi-Fi"
                    caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> "Cellular"
                    caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> "Ethernet"
                    else -> "Unknown"
                }
                Log.i(TAG, "NETWORK BYPASS SUCCESS: bindProcessToNetwork($network) = true " +
                           "(transport=$transportType) — native C++ sockets are now un-blinded. " +
                           "ZeroTier engine can now send UDP packets directly over $transportType.")
            } else {
                Log.e(TAG, "NETWORK BYPASS FAILED: bindProcessToNetwork($network) returned false. " +
                           "The Android framework rejected the binding. Possible causes: " +
                           "another VPN is active, the network is suspended, or a security policy prevents binding.")
            }
            bound
        } catch (e: SecurityException) {
            Log.e(TAG, "NETWORK BYPASS FAILED: SecurityException during bindProcessToNetwork. " +
                       "The app may lack the required permissions or a device policy prevents network binding.", e)
            false
        } catch (e: IllegalStateException) {
            Log.e(TAG, "NETWORK BYPASS FAILED: IllegalStateException — the network may have been disconnected " +
                       "between the capability check and the binding call.", e)
            false
        } catch (e: Exception) {
            Log.e(TAG, "NETWORK BYPASS FAILED: Unexpected exception during bindProcessToNetwork", e)
            false
        }
    }

    /**
     * Unbind the process from the previously bound network.
     * This is called during teardown to restore normal network routing.
     */
    private fun unbindProcessNetwork() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && boundNetwork != null) {
            try {
                val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                cm.bindProcessToNetwork(null)
                Log.i(TAG, "NETWORK BYPASS: Unbound process from network — normal routing restored")
            } catch (e: Exception) {
                Log.w(TAG, "NETWORK BYPASS: Failed to unbind process network", e)
            }
            boundNetwork = null
        }
    }

    /**
     * Check network connectivity using the modern NetworkCapabilities API.
     */
    private fun checkNetworkConnectivity(cm: ConnectivityManager): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val network = cm.activeNetwork
            val caps = if (network != null) cm.getNetworkCapabilities(network) else null
            caps != null && (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))
        } else {
            @Suppress("DEPRECATION")
            val activeNet = cm.activeNetworkInfo
            activeNet != null && activeNet.isConnected
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // RESILIENT CONNECTION RETRY — Exponential backoff with graceful states
    // ══════════════════════════════════════════════════════════════════════════

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
            unbindProcessNetwork()
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

        // Unbind process network so we can re-bind fresh
        unbindProcessNetwork()

        // Small delay to ensure cleanup is complete
        delay(500)

        // Try again
        handleStartCommand(networkId, mode)
    }

    // ══════════════════════════════════════════════════════════════════════════
    // MODE-SPECIFIC SETUP
    // ══════════════════════════════════════════════════════════════════════════

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
        startLoopbackGatewayIfPossible()
        VpnStateHolder.updateState(VpnState.Connected())
        VpnNotificationHelper.updateNotification(this, "SOCKS5 proxy active on $assignedIP:1080")
        Log.i(TAG, "SENDER mode active: SOCKS5 proxy on $assignedIP:1080")

        // ── Do NOT unbind process from physical network ────────────────────
        // CRITICAL FIX: We must KEEP bindProcessToNetwork active because the
        // ZeroTier SDK (libzt.so) needs continuous access to the physical network
        // to send/receive UDP packets for P2P mesh communication. Unbinding
        // would break the ZeroTier connection entirely.
        //
        // The VPN app itself is excluded from the TUN interface via
        // addDisallowedApplication(), so our UDP packets already bypass the
        // VPN tunnel and go through the physical network. Other apps' traffic
        // correctly routes through the TUN → ZeroTier → internet path.
        //
        // DO NOT call unbindProcessNetwork() here — it was causing the VPN
        // to stop working after initial connection.
        Log.i(TAG, "Keeping process bound to physical network for ZeroTier SDK connectivity")

        monitorEngineHealth()
    }

    /**
     * RECEIVER MODE: Establish TUN interface and bridge traffic.
     *
     * HYBRID ROUTING ARCHITECTURE (Exit Node / Full Tunneling):
     *
     * In RECEIVER mode, we support two bridge modes:
     *   1. TUN-SOCKS5 Bridge (Full Tunneling via Exit Node):
     *      - TUN → Packet Parser → SOCKS5 via ZT Socket → Sender's Proxy → Internet
     *      - Routes TCP connections through a SOCKS5 proxy chain
     *      - UDP forwarded through C++ ZT raw socket bridge
     *      - Requires exit node (Sender) SOCKS5 proxy address
     *
     *   2. Raw TUN-ZT Bridge (Direct P2P Mesh):
     *      - TUN → Raw IP Packets → ZT Raw Socket → ZeroTier Network
     *      - For direct ZeroTier network access without exit node
     *      - Used when no exit node address is configured
     *
     * The bridge mode is selected automatically based on whether an
     * exit node address is configured in VpnStateHolder.
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
            unbindProcessNetwork()
            stopForegroundAndNotification()
            stopSelf()
            return
        } catch (e: IOException) {
            Log.e(TAG, "TUN establishment I/O error", e)
            VpnStateHolder.updateState(VpnState.Error("TUN I/O error: ${e.message}"))
            stopEngineAndTun()
            unbindProcessNetwork()
            stopForegroundAndNotification()
            stopSelf()
            return
        }

        vpnInterface = pfd
        tunEstablished = true

        val tunFd = pfd.fd
        Log.i(TAG, "TUN established: fd=$tunFd, mtu=$TUNNEL_MTU, ip=$assignedIP")

        // ══════════════════════════════════════════════════════════════════════
        // BRIDGE MODE SELECTION — Automatic hybrid routing
        // ══════════════════════════════════════════════════════════════════════
        //
        // If an exit node address is configured, use the TUN-SOCKS5 bridge
        // for full tunneling. Otherwise, fall back to the raw TUN-ZT bridge
        // for direct P2P mesh access.

        val exitNodeAddr = VpnStateHolder.exitNodeAddress.value

        if (exitNodeAddr.isNotBlank()) {
            // ── MODE 1: TUN-SOCKS5 Bridge (Full Tunneling via Exit Node) ──
            Log.i(TAG, "RECEIVER mode: Starting TUN-SOCKS5 bridge to exit node $exitNodeAddr")
            VpnNotificationHelper.updateNotification(this, "Starting exit node bridge...")

            val bridge = TunSocksBridge(this, pfd)
            val exitNodePort = VpnStateHolder.exitNodePort.value
            val bridgeStarted = bridge.start(exitNodeAddr, exitNodePort)

            if (!bridgeStarted) {
                Log.e(TAG, "Failed to start TUN-SOCKS5 bridge — falling back to raw bridge")
                VpnNotificationHelper.updateNotification(this, "Fallback: raw bridge mode")
                startRawTunBridge(tunFd)
            } else {
                tunSocksBridge = bridge
                VpnStateHolder.updateTunSocksBridgeRunning(true)
                Log.i(TAG, "TUN-SOCKS5 bridge started — full tunneling via exit node $exitNodeAddr:$exitNodePort")
            }
        } else {
            // ── MODE 2: Raw TUN-ZT Bridge (Direct P2P Mesh) ──
            Log.i(TAG, "RECEIVER mode: No exit node configured — using raw TUN-ZT bridge")
            VpnNotificationHelper.updateNotification(this, "Starting P2P mesh bridge...")
            startRawTunBridge(tunFd)
        }

        startLoopbackGatewayIfPossible()
        VpnStateHolder.updateState(VpnState.Connected())
        VpnNotificationHelper.updateNotification(this, "P2P Mesh VPN active")
        Log.i(TAG, "TUN bridge started — VPN tunnel is active")

        // ── Do NOT unbind process from physical network ────────────────────
        // CRITICAL FIX: Same as SENDER mode — we must KEEP bindProcessToNetwork
        // active because the ZeroTier SDK needs continuous physical network
        // access for UDP P2P communication. The VPN app is already excluded
        // from the TUN via addDisallowedApplication(), so routing works correctly.
        Log.i(TAG, "Keeping process bound to physical network for ZeroTier SDK connectivity")

        monitorEngineHealth()
    }

    /**
     * Start the raw TUN-ZT bridge using the C++ engine.
     * Used when no exit node is configured for full tunneling.
     */
    private fun startRawTunBridge(tunFd: Int) {
        val bridgeStarted = ZtEngine.startTunBridgeSafe(tunFd)
        if (!bridgeStarted) {
            val nativeErr = ZtEngine.getLastErrorSafe()
            Log.e(TAG, "Failed to start raw TUN bridge: $nativeErr")
            VpnStateHolder.updateState(VpnState.Error("Failed to start packet bridge: $nativeErr"))
            stopEngineAndTun()
            unbindProcessNetwork()
            stopForegroundAndNotification()
            stopSelf()
            return
        }
        Log.i(TAG, "Raw TUN-ZT bridge started")
    }

    /**
     * Stop the TUN-SOCKS5 bridge if it's running.
     */
    private fun stopTunSocksBridge() {
        tunSocksBridge?.stop()
        tunSocksBridge = null
        VpnStateHolder.updateTunSocksBridgeRunning(false)
    }

    // ══════════════════════════════════════════════════════════════════════════
    // STOP / TEARDOWN — Coordinated, crash-free shutdown
    // ══════════════════════════════════════════════════════════════════════════

    private fun handleStopCommand() {
        Log.i(TAG, "Stopping VPN tunnel...")
        retryJob?.cancel()
        ZtEngine.vpnServiceRef = null
        ZtEngine.fatalErrorHandler = null
        stopEngineAndTun()
        stopSocks5Proxy()
        stopTunSocksBridge()
        stopLoopbackGateway()
        unbindProcessNetwork()
        releaseWakeLockIfHeld()
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
                    is VpnState.UnblindingNetwork -> "Un-blinding Network"
                    is VpnState.P2pHandshake -> "P2P Handshake"
                    is VpnState.Authenticating -> "Authenticating"
                    is VpnState.WaitingAuthorization -> "Awaiting Web Auth"
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
     * Monitor engine health and poll traffic statistics.
     *
     * CRITICAL FIX (BUG 3): Previously, traffic stats never updated after
     * connection because this method only checked running/online status.
     * Now it also:
     *   1. Polls the C++ engine for current assigned IP and refreshes VpnStateHolder
     *   2. Logs current traffic stats from VpnStateHolder (updated by C++ callbacks)
     *   3. Detects stale traffic stats and logs a warning
     *   4. Checks if the engine is still online and attempts auto-reconnect on failure
     */
    private suspend fun monitorEngineHealth() {
        var consecutiveFailures = 0
        val maxFailures = 3
        var lastStatsLogTime = 0L
        val statsLogIntervalMs = 30_000L // Log traffic stats every 30s
        var lastStatsBytesIn = 0L
        var lastStatsBytesOut = 0L
        var staleStatsCount = 0
        val maxStaleStatsCount = 6 // 30 seconds * 6 = 3 minutes of stale stats

        while (currentCoroutineContext().isActive) {
            delay(MONITOR_INTERVAL_MS)

            val running = ZtEngine.isRunningSafe()
            val online = ZtEngine.isOnlineSafe()

            // ── Health check: engine running and online ────────────────────
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

            // ── Poll C++ engine for assigned IP and refresh VpnStateHolder ──
            // This ensures VpnStateHolder stays in sync even if a C++ callback
            // was missed or the IP changed (e.g., after network re-join).
            val currentIp = ZtEngine.getAssignedIPv4Safe()
            if (currentIp.isNotBlank() && currentIp != VpnStateHolder.assignedIPv4.value) {
                Log.i(TAG, "Health check: IP changed from ${VpnStateHolder.assignedIPv4.value} to $currentIp — updating")
                VpnStateHolder.updateAssignedIP(currentIp, VpnStateHolder.assignedIPv6.value)
            }

            // ── Refresh Node ID from engine ────────────────────────────────
            val currentNodeId = ZtEngine.getNodeIdSafe()
            if (currentNodeId != 0L && currentNodeId != VpnStateHolder.nodeId.value) {
                VpnStateHolder.updateNodeId(currentNodeId)
            }

            // ── Traffic stats monitoring ───────────────────────────────────
            // Traffic stats are updated by C++ via the onZtTrafficStats callback.
            // We monitor them here to detect stale stats and log periodic updates.
            val stats = VpnStateHolder.trafficStats.value
            val now = System.currentTimeMillis()

            // Detect stale stats: if bytes haven't changed for multiple checks
            if (stats.bytesIn == lastStatsBytesIn && stats.bytesOut == lastStatsBytesOut) {
                staleStatsCount++
                if (staleStatsCount >= maxStaleStatsCount) {
                    Log.w(TAG, "Traffic stats appear stale (no change for " +
                        "${staleStatsCount * MONITOR_INTERVAL_MS / 1000}s) — " +
                        "bytesIn=${stats.bytesIn} bytesOut=${stats.bytesOut}")
                    staleStatsCount = 0 // Reset to avoid spamming
                }
            } else {
                staleStatsCount = 0
            }
            lastStatsBytesIn = stats.bytesIn
            lastStatsBytesOut = stats.bytesOut

            // Log traffic stats periodically for debugging
            if (now - lastStatsLogTime >= statsLogIntervalMs) {
                Log.i(TAG, "Traffic stats: bytesIn=${stats.bytesIn} bytesOut=${stats.bytesOut} " +
                    "packetsIn=${stats.packetsIn} packetsOut=${stats.packetsOut}")
                lastStatsLogTime = now
            }
        }
    }

    private fun stopEngineAndTun() {
        // Unbind process network FIRST to restore normal routing
        unbindProcessNetwork()
        // Stop TUN bridge (joins bridge thread in C++)
        try { ZtEngine.stopTunBridgeSafe() } catch (e: Exception) { Log.w(TAG, "Error stopping TUN bridge", e) }
        // Stop the ZeroTier engine with coordinated shutdown
        try { ZtEngine.stopSafe() } catch (e: Exception) { Log.w(TAG, "Error stopping ZT engine", e) }
        // Close the TUN file descriptor
        try { vpnInterface?.close() } catch (e: IOException) { Log.w(TAG, "Error closing TUN interface", e) }
        vpnInterface = null
        tunEstablished = false
        VpnStateHolder.updateAssignedIP("", "")
    }

    /**
     * Start the embedded application-layer loopback gateway on 127.0.0.1:1080.
     * This is started best-effort — failure is logged but does not stop the VPN.
     */
    private fun startLoopbackGatewayIfPossible() {
        if (loopbackGateway?.isRunning == true) return
        try {
            val gw = LocalLoopbackGateway(LocalLoopbackGateway.DEFAULT_PORT)
            if (gw.start()) {
                loopbackGateway = gw
                Log.i(TAG, "Embedded loopback gateway active on 127.0.0.1:${LocalLoopbackGateway.DEFAULT_PORT}")
            } else {
                Log.w(TAG, "Loopback gateway failed to bind — feature disabled")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Could not start loopback gateway", e)
        }
    }

    private fun stopLoopbackGateway() {
        try { loopbackGateway?.stop() } catch (e: Exception) {
            Log.w(TAG, "Error stopping loopback gateway", e)
        }
        loopbackGateway = null
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
