package com.vpnengine.nativecore

import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * VpnStateHolder — Centralized state container for the VPN engine.
 *
 * Single source of truth for:
 *   - VPN connection state (VpnState)
 *   - ZeroTier assigned IP addresses
 *   - Traffic statistics
 *   - Node ID (both Long from C++ and formatted 10-digit String from identity.public)
 *   - Operating mode (Sender / Receiver)
 *
 * Updated from C++ JNI callbacks and Kotlin service layer.
 * Observed by VpnViewModel for Compose UI reactivity.
 */
object VpnStateHolder {

    private const val TAG = "VpnStateHolder"

    // ── Connection State ────────────────────────────────────────────────────

    private val _vpnState = MutableStateFlow<VpnState>(VpnState.Disconnected)
    val vpnState: StateFlow<VpnState> = _vpnState.asStateFlow()
    val currentValue: VpnState get() = _vpnState.value

    // ── Assigned IPs ────────────────────────────────────────────────────────

    private val _assignedIPv4 = MutableStateFlow("")
    val assignedIPv4: StateFlow<String> = _assignedIPv4.asStateFlow()

    private val _assignedIPv6 = MutableStateFlow("")
    val assignedIPv6: StateFlow<String> = _assignedIPv6.asStateFlow()

    // ── Traffic Stats ───────────────────────────────────────────────────────

    data class TrafficStats(
        val bytesIn: Long = 0,
        val bytesOut: Long = 0,
        val packetsIn: Long = 0,
        val packetsOut: Long = 0
    )

    private val _trafficStats = MutableStateFlow(TrafficStats())
    val trafficStats: StateFlow<TrafficStats> = _trafficStats.asStateFlow()

    // ── Node ID ─────────────────────────────────────────────────────────────

    private val _nodeId = MutableStateFlow(0L)
    val nodeId: StateFlow<Long> = _nodeId.asStateFlow()

    /**
     * The 10-digit ZeroTier Node ID as a formatted string.
     * This is populated from two sources:
     *   1. The C++ engine callback (onZtAssignedIP) provides the Long value
     *   2. The identity.public file provides a persistent string even before C++ starts
     *
     * Format: 10 lowercase hex characters (e.g., "a1b2c3d4e5")
     */
    private val _nodeIdString = MutableStateFlow("")
    val nodeIdString: StateFlow<String> = _nodeIdString.asStateFlow()

    // ── Operating Mode ──────────────────────────────────────────────────────

    enum class VpnMode {
        /** Sender: Provides internet to other peers via SOCKS5 proxy */
        SENDER,
        /** Receiver: Consumes internet from a Sender peer via VPN tunnel */
        RECEIVER
    }

    private val _mode = MutableStateFlow(VpnMode.RECEIVER)
    val mode: StateFlow<VpnMode> = _mode.asStateFlow()

    // ── Sender Proxy Config ─────────────────────────────────────────────────

    private val _senderProxyAddress = MutableStateFlow("")
    val senderProxyAddress: StateFlow<String> = _senderProxyAddress.asStateFlow()

    private val _senderProxyPort = MutableStateFlow(1080)
    val senderProxyPort: StateFlow<Int> = _senderProxyPort.asStateFlow()

    private val _socks5ProxyRunning = MutableStateFlow(false)
    val socks5ProxyRunning: StateFlow<Boolean> = _socks5ProxyRunning.asStateFlow()

    // ── Update Methods ──────────────────────────────────────────────────────

    fun updateState(state: VpnState) {
        val prev = _vpnState.value
        Log.d(TAG, "State: $prev → $state")
        _vpnState.value = state
    }

    fun updateAssignedIP(ipv4: String, ipv6: String) {
        _assignedIPv4.value = ipv4
        _assignedIPv6.value = ipv6
        Log.d(TAG, "Assigned IP: ipv4=$ipv4 ipv6=$ipv6")
    }

    fun updateTrafficStats(bytesIn: Long, bytesOut: Long, packetsIn: Long, packetsOut: Long) {
        _trafficStats.value = TrafficStats(bytesIn, bytesOut, packetsIn, packetsOut)
    }

    fun updateNodeId(id: Long) {
        _nodeId.value = id
        // Also update the string representation
        if (id != 0L) {
            val formatted = String.format(java.util.Locale.US, "%010x", id)
            if (_nodeIdString.value != formatted) {
                _nodeIdString.value = formatted
                Log.d(TAG, "Node ID string updated: $formatted")
            }
        }
    }

    /**
     * Update the Node ID string directly from the identity.public file.
     * This provides a persistent Node ID even before the C++ engine is started.
     */
    fun updateNodeIdString(idString: String) {
        if (idString.isNotBlank() && _nodeIdString.value != idString) {
            _nodeIdString.value = idString
            Log.d(TAG, "Node ID string from file: $idString")
        }
    }

    fun updateMode(mode: VpnMode) {
        _mode.value = mode
        Log.d(TAG, "Mode: $mode")
    }

    fun updateSenderProxyConfig(address: String, port: Int) {
        _senderProxyAddress.value = address
        _senderProxyPort.value = port
    }

    fun updateSocks5ProxyRunning(running: Boolean) {
        _socks5ProxyRunning.value = running
    }

    fun reset() {
        _vpnState.value = VpnState.Disconnected
        _assignedIPv4.value = ""
        _assignedIPv6.value = ""
        _trafficStats.value = TrafficStats()
        _nodeId.value = 0L
        _nodeIdString.value = ""
        _socks5ProxyRunning.value = false
        _senderProxyAddress.value = ""
        _senderProxyPort.value = 1080
        // NOTE: _mode is NOT reset — user preference persists across connections
    }
}
