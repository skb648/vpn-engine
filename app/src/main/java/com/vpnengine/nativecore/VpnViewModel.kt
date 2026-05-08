package com.vpnengine.nativecore

import android.app.Application
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * VpnViewModel — UI state management for ZeroTier P2P Mesh VPN.
 *
 * BULLETPROOF LIFECYCLE (v5):
 *   - Handles new states: P2pHandshake, Authenticating, Reconnecting
 *   - Verification loop accounts for longer timeouts (120s)
 *   - Grace period extended for strict NAT/ISP scenarios
 *   - Reconnecting state prevents false error flags
 */
class VpnViewModel(application: Application) : AndroidViewModel(application) {

    companion object {
        private const val TAG = "VpnViewModel"
        private const val VERIFY_INTERVAL_MS = 2000L
        private const val NETWORK_ID_LENGTH = 16
        // Extended grace period for strict NAT/ISP — 30 seconds
        // (was 15s, but P2P handshake alone can take 20-30s)
        private const val ENGINE_STARTUP_GRACE_MS = 30_000L
    }

    private var connectingStateStartTime = 0L

    private val serverConfig = ServerConfig(application)

    // ── Network ID ─────────────────────────────────────────────────────────

    private val _networkId = MutableStateFlow(0L)
    val networkId: StateFlow<Long> = _networkId.asStateFlow()

    private val _networkIdDisplay = MutableStateFlow("")
    val networkIdDisplay: StateFlow<String> = _networkIdDisplay.asStateFlow()

    // ── VPN State ──────────────────────────────────────────────────────────

    private val _vpnState = MutableStateFlow<VpnState>(VpnStateHolder.currentValue)
    val vpnState: StateFlow<VpnState> = _vpnState.asStateFlow()

    // ── Traffic Stats ──────────────────────────────────────────────────────

    val trafficStats: StateFlow<VpnStateHolder.TrafficStats> = VpnStateHolder.trafficStats
    val assignedIPv4: StateFlow<String> = VpnStateHolder.assignedIPv4
    val nodeId: StateFlow<Long> = VpnStateHolder.nodeId

    // ── Mode ───────────────────────────────────────────────────────────────

    val mode: StateFlow<VpnStateHolder.VpnMode> = VpnStateHolder.mode

    // ── Sender Proxy Info ──────────────────────────────────────────────────

    val senderProxyAddress: StateFlow<String> = VpnStateHolder.senderProxyAddress
    val senderProxyPort: StateFlow<Int> = VpnStateHolder.senderProxyPort
    val socks5ProxyRunning: StateFlow<Boolean> = VpnStateHolder.socks5ProxyRunning

    // ── Events ─────────────────────────────────────────────────────────────

    private val _permissionEvent = MutableSharedFlow<Intent>(extraBufferCapacity = 1)
    val permissionEvent: SharedFlow<Intent> = _permissionEvent.asSharedFlow()

    private val _snackBarEvent = MutableSharedFlow<String>(extraBufferCapacity = 1)
    val snackBarEvent: SharedFlow<String> = _snackBarEvent.asSharedFlow()

    private var verifyJob: Job? = null

    init {
        loadNetworkIdFromDataStore()
        observeVpnStateHolder()
        startVerificationLoop()
    }

    // ── Network ID Management ──────────────────────────────────────────────

    private fun loadNetworkIdFromDataStore() {
        viewModelScope.launch {
            try {
                val storedId = serverConfig.networkId.first()
                if (storedId.isNotBlank()) {
                    try {
                        val id = storedId.toLong(16)
                        _networkId.value = id
                        _networkIdDisplay.value = "%016x".format(id)
                        Log.d(TAG, "Loaded Network ID from DataStore: $storedId → $id")
                    } catch (e: NumberFormatException) {
                        Log.w(TAG, "Invalid Network ID in DataStore: $storedId")
                    }
                }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to load Network ID from DataStore: ${e.message}")
            }
        }
    }

    fun updateNetworkId(hexString: String) {
        val cleaned = hexString.trim().lowercase()
            .filter { it in '0'..'9' || it in 'a'..'f' }

        if (cleaned.length != NETWORK_ID_LENGTH) {
            Log.w(TAG, "Invalid Network ID length: ${cleaned.length} (need $NETWORK_ID_LENGTH)")
            _snackBarEvent.tryEmit("Network ID must be exactly 16 hex characters.")
            return
        }

        try {
            val id = cleaned.toLong(16)
            if (id == 0L) {
                _snackBarEvent.tryEmit("Network ID cannot be all zeros.")
                return
            }
            _networkId.value = id
            _networkIdDisplay.value = "%016x".format(id)
            viewModelScope.launch { serverConfig.saveNetworkId(cleaned) }
            Log.i(TAG, "Network ID updated: $cleaned → $id")
        } catch (e: NumberFormatException) {
            Log.w(TAG, "Invalid Network ID: $hexString")
            _snackBarEvent.tryEmit("Invalid Network ID. Must be 16 hex characters.")
        }
    }

    // ── Mode Management ────────────────────────────────────────────────────

    fun setMode(mode: VpnStateHolder.VpnMode) {
        if (_vpnState.value is VpnState.Connected || _vpnState.value is VpnState.Connecting
            || _vpnState.value is VpnState.InitializingNode || _vpnState.value is VpnState.P2pHandshake
            || _vpnState.value is VpnState.JoiningMesh || _vpnState.value is VpnState.Authenticating
            || _vpnState.value is VpnState.WaitingAuthorization || _vpnState.value is VpnState.Reconnecting) {
            _snackBarEvent.tryEmit("Disconnect first before changing mode")
            return
        }
        VpnStateHolder.updateMode(mode)
        Log.i(TAG, "Mode changed to: $mode")
    }

    // ── Connection Management ──────────────────────────────────────────────

    fun connect() {
        val app = getApplication<Application>()

        if (!ZtEngine.isNativeLibraryLoaded()) {
            val error = ZtEngine.getNativeLoadError().ifEmpty { "Native engine failed to load" }
            Log.e(TAG, "Cannot connect: $error")
            _vpnState.value = VpnState.Error(error)
            _snackBarEvent.tryEmit(error)
            return
        }

        val currentNetworkId = _networkId.value
        val currentDisplay = _networkIdDisplay.value
        if (currentNetworkId == 0L || currentDisplay.isBlank() || currentDisplay.length != NETWORK_ID_LENGTH) {
            _snackBarEvent.tryEmit("Enter a valid 16-character hex Network ID before connecting.")
            return
        }
        try {
            val parsed = currentDisplay.toLong(16)
            if (parsed != currentNetworkId) {
                _snackBarEvent.tryEmit("Network ID mismatch. Please re-enter.")
                return
            }
        } catch (e: NumberFormatException) {
            _snackBarEvent.tryEmit("Network ID contains invalid characters.")
            return
        }

        val prepareIntent = VpnService.prepare(app)
        if (prepareIntent != null) {
            Log.i(TAG, "VPN permission not yet granted — requesting")
            _permissionEvent.tryEmit(prepareIntent)
            return
        }

        connectingStateStartTime = System.currentTimeMillis()
        VpnStateHolder.updateState(VpnState.Connecting)
        startVpnService()
    }

    fun disconnect() {
        Log.i(TAG, "User requested disconnect")
        val app = getApplication<Application>()
        val intent = Intent(app, VpnTunnelService::class.java).apply {
            action = VpnTunnelService.ACTION_STOP
        }
        app.startService(intent)
    }

    fun onVpnPermissionResult(granted: Boolean) {
        if (granted) {
            Log.i(TAG, "VPN permission granted — starting service")
            connectingStateStartTime = System.currentTimeMillis()
            VpnStateHolder.updateState(VpnState.Connecting)
            startVpnService()
        } else {
            Log.w(TAG, "VPN permission denied")
            VpnStateHolder.updateState(VpnState.Error("VPN permission denied"))
            _snackBarEvent.tryEmit("VPN permission is required")
        }
    }

    private fun startVpnService() {
        val app = getApplication<Application>()
        val networkId = _networkId.value
        val currentMode = VpnStateHolder.mode.value

        val intent = Intent(app, VpnTunnelService::class.java).apply {
            action = VpnTunnelService.ACTION_START
            putExtra(VpnTunnelService.EXTRA_NETWORK_ID, networkId)
            putExtra(VpnTunnelService.EXTRA_MODE, currentMode.name)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            app.startForegroundService(intent)
        } else {
            app.startService(intent)
        }

        Log.i(TAG, "VpnTunnelService started (networkId=%016x, mode=%s)".format(networkId, currentMode))
    }

    // ── State Observation ──────────────────────────────────────────────────

    private fun observeVpnStateHolder() {
        viewModelScope.launch {
            VpnStateHolder.vpnState.collect { state ->
                _vpnState.value = state
                if (state is VpnState.Error) {
                    _snackBarEvent.tryEmit(state.message)
                }
            }
        }
    }

    /**
     * Verification loop: periodically checks that the Kotlin state
     * matches the actual C++ engine state.
     *
     * CRITICAL FIX (v5): Extended grace period to 30s for strict NAT/ISP.
     * Also, Reconnecting state is NOT flagged as an error.
     */
    private fun startVerificationLoop() {
        verifyJob?.cancel()
        verifyJob = viewModelScope.launch {
            while (isActive) {
                delay(VERIFY_INTERVAL_MS)
                when (val state = _vpnState.value) {
                    is VpnState.Connected -> {
                        if (!ZtEngine.isRunningSafe()) {
                            Log.w(TAG, "State=Connected but engine not running — reverting")
                            VpnStateHolder.updateState(VpnState.Error("Connection lost unexpectedly"))
                        }
                    }
                    is VpnState.Error -> {
                        if (ZtEngine.isRunningSafe()) {
                            Log.w(TAG, "State=Error but engine still running — stopping engine")
                            ZtEngine.stopSafe()
                        }
                    }
                    is VpnState.Reconnecting -> {
                        // Don't interfere with the reconnecting process
                        // The service layer handles the retry logic
                    }
                    is VpnState.InitializingNode,
                    is VpnState.P2pHandshake,
                    is VpnState.JoiningMesh,
                    is VpnState.Authenticating,
                    is VpnState.WaitingAuthorization,
                    is VpnState.Connecting -> {
                        val timeInState = System.currentTimeMillis() - connectingStateStartTime
                        if (timeInState < ENGINE_STARTUP_GRACE_MS) {
                            Log.d(TAG, "Grace period: ${timeInState}ms in ${state::class.simpleName}, skipping check")
                        } else if (!ZtEngine.isRunningSafe()) {
                            // Only flag as error if the engine is truly dead
                            // AND we're not in the middle of a retry
                            if (!ZtEngine.isStoppingSafe()) {
                                Log.w(TAG, "Engine died during ${state::class.simpleName} (after ${timeInState}ms)")
                                VpnStateHolder.updateState(VpnState.Error("Engine stopped unexpectedly. Try again."))
                            }
                        }
                    }
                    is VpnState.Disconnected -> {
                        // Do NOT stop engine here — a new connection may be starting.
                    }
                }
            }
        }
    }

    override fun onCleared() {
        super.onCleared()
        verifyJob?.cancel()
    }
}
