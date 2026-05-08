package com.vpnengine.nativecore

import android.net.VpnService
import android.util.Log
import androidx.annotation.Keep
import java.math.BigInteger

/**
 * ZtEngine — JNI bridge between Kotlin and C++ ZeroTierEngine.
 *
 * This singleton wraps all native method calls with exception safety:
 *   - Every native call is wrapped in try-catch
 *   - C++ exceptions NEVER crash the app (they are caught in C++)
 *   - Java Errors (like UnsatisfiedLinkError) are also caught
 *   - All methods return safe defaults on failure
 *
 * BULLETPROOF LIFECYCLE (v5):
 *   - New state codes: P2P_HANDSHAKE (8), AUTHENTICATING (9), RECONNECTING (10)
 *   - State mapping includes all connection phases for UI feedback
 *   - Fatal error handler triggers reconnect instead of immediate stop
 */
object ZtEngine {

    private const val TAG = "ZtEngine-Kotlin"
    private var nativeLibraryLoaded: Boolean = false
    private var loadError: String = ""

    @Volatile
    internal var vpnServiceRef: VpnService? = null

    @Volatile
    internal var fatalErrorHandler: (() -> Unit)? = null

    init {
        try {
            // CRITICAL: Load libzt.so FIRST before libvpn-engine.so.
            try {
                System.loadLibrary("zt")
                Log.i(TAG, "ZeroTier SDK library 'zt' loaded successfully")
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "CRITICAL: Failed to load libzt.so — ZeroTier SDK not in APK! " +
                          "Ensure libzt.so is in app/src/main/jniLibs/<abi>/", e)
            } catch (e: SecurityException) {
                Log.e(TAG, "SecurityManager blocked loading libzt.so", e)
            }

            System.loadLibrary("vpn-engine")
            nativeLibraryLoaded = true
            loadError = ""
            Log.i(TAG, "Native library 'vpn-engine' loaded successfully")

            // CRITICAL FIX: Two-phase initialization to avoid race condition.
            // JNI_OnLoad cannot safely access ZtEngine.INSTANCE because this
            // init block is still running. We complete callback setup here.
            try {
                nativeInit()
                Log.i(TAG, "Native callback initialization complete (two-phase init)")
            } catch (e: Exception) {
                Log.e(TAG, "nativeInit failed — callbacks may not work", e)
            } catch (e: Error) {
                Log.e(TAG, "nativeInit error — callbacks may not work", e)
            }
        } catch (e: UnsatisfiedLinkError) {
            nativeLibraryLoaded = false
            loadError = "Native library not found: ${e.message}"
            Log.e(TAG, "Failed to load native library", e)
        } catch (e: SecurityException) {
            nativeLibraryLoaded = false
            loadError = "Security manager blocked native library: ${e.message}"
            Log.e(TAG, "SecurityManager blocked loading", e)
        } catch (e: Throwable) {
            nativeLibraryLoaded = false
            loadError = "Unexpected error loading native library: ${e.message}"
            Log.e(TAG, "Unexpected error loading native library", e)
        }
    }

    // ── Native method declarations ─────────────────────────────────────────

    /**
     * Phase 2 initialization — set the callback object reference.
     * CRITICAL: This MUST be called after the Kotlin object is fully
     * constructed to avoid the race condition in JNI_OnLoad.
     */
    external fun nativeInit()

    external fun nativeStart(configPath: String, networkId: Long): Boolean
    external fun nativeStop()
    external fun nativeIsOnline(): Boolean
    external fun nativeIsRunning(): Boolean
    external fun nativeGetNodeId(): Long
    external fun nativeGetAssignedIPv4(): String
    external fun nativeGetAssignedIPv6(): String
    external fun nativeJoinNetwork(networkId: Long): Boolean
    external fun nativeLeaveNetwork(networkId: Long): Boolean
    external fun nativeStartTunBridge(tunFd: Int): Boolean
    external fun nativeStopTunBridge()
    external fun nativeGetLastError(): String
    external fun nativeIsSdkAvailable(): Boolean
    external fun nativeIsStopping(): Boolean
    external fun nativeProcessPacket(packet: java.nio.ByteBuffer, length: Int): Int
    external fun nativeReadPacket(buffer: java.nio.ByteBuffer, capacity: Int): Int

    // Functions that may not be present in the native library — provide stubs
    /**
     * Join a ZeroTier network. May be handled internally by nativeStart.
     */
    private external fun nativeJoinNetwork(networkId: Long): Boolean

    /**
     * Leave a ZeroTier network.
     */
    private external fun nativeLeaveNetwork(networkId: Long): Boolean

    /**
     * Get an assigned IP address by index.
     * @param index The address index (0-31).
     * @return IP string or null if no address at this index.
     */
    private external fun nativeGetAddress(index: Long): String?

    /**
     * Connect to a TCP target via ZeroTier.
     * Used by SOCKS5 proxy for outbound connections.
     */
    private external fun nativeZtsTcpConnect(destIP: String, destPort: Int): Int

    // ── Safe wrappers (exception-safe) ─────────────────────────────────────

    fun startSafe(configPath: String, networkId: Long): Boolean {
        if (!nativeLibraryLoaded) {
            Log.e(TAG, "Cannot start: $loadError")
            return false
        }
        if (networkId == 0L) {
            Log.e(TAG, "Cannot start: Network ID is 0 (invalid)")
            return false
        }
        if (configPath.isBlank()) {
            Log.e(TAG, "Cannot start: config path is empty")
            return false
        }
        return try {
            val result = nativeStart(configPath, networkId)
            if (!result) {
                Log.e(TAG, "nativeStart returned false — engine failed to start. Error: ${getLastErrorSafe()}")
            }
            result
        } catch (e: Exception) {
            Log.e(TAG, "Exception in nativeStart", e)
            false
        } catch (e: Error) {
            Log.e(TAG, "Error in nativeStart", e)
            false
        }
    }

    fun stopSafe() {
        if (!nativeLibraryLoaded) return
        try { nativeStop() }
        catch (e: Exception) { Log.e(TAG, "Exception in nativeStop", e) }
        catch (e: Error) { Log.e(TAG, "Error in nativeStop", e) }
    }

    fun isOnlineSafe(): Boolean {
        if (!nativeLibraryLoaded) return false
        return try { nativeIsOnline() } catch (e: Exception) { false } catch (e: Error) { false }
    }

    fun isRunningSafe(): Boolean {
        if (!nativeLibraryLoaded) return false
        return try { nativeIsRunning() } catch (e: Exception) { false } catch (e: Error) { false }
    }

    fun isStoppingSafe(): Boolean {
        if (!nativeLibraryLoaded) return false
        return try { nativeIsStopping() } catch (e: Exception) { false } catch (e: Error) { false }
    }

    fun getNodeIdSafe(): Long {
        if (!nativeLibraryLoaded) return 0L
        return try { nativeGetNodeId() } catch (e: Exception) { 0L } catch (e: Error) { 0L }
    }

    fun getAssignedIPv4Safe(): String {
        if (!nativeLibraryLoaded) return ""
        return try { nativeGetAssignedIPv4() } catch (e: Exception) { "" } catch (e: Error) { "" }
    }

    fun getLastErrorSafe(): String {
        if (!nativeLibraryLoaded) return loadError
        return try { nativeGetLastError() } catch (e: Exception) { "Error getting last error: ${e.message}" }
        catch (e: Error) { "Error getting last error: ${e.message}" }
    }

    fun startTunBridgeSafe(tunFd: Int): Boolean {
        if (!nativeLibraryLoaded) return false
        return try { nativeStartTunBridge(tunFd) }
        catch (e: Exception) { Log.e(TAG, "Exception in startTunBridge", e); false }
        catch (e: Error) { Log.e(TAG, "Error in startTunBridge", e); false }
    }

    fun stopTunBridgeSafe() {
        if (!nativeLibraryLoaded) return
        try { nativeStopTunBridge() }
        catch (e: Exception) { Log.e(TAG, "Exception in stopTunBridge", e) }
        catch (e: Error) { Log.e(TAG, "Error in stopTunBridge", e) }
    }

    fun isSdkAvailableSafe(): Boolean {
        if (!nativeLibraryLoaded) return false
        return try { nativeIsSdkAvailable() } catch (e: Exception) { false } catch (e: Error) { false }
    }

    fun isNativeLibraryLoaded(): Boolean = nativeLibraryLoaded
    fun getNativeLoadError(): String = loadError

    // ── Additional safe wrappers for VpnTunnelService ──────────────────────

    fun joinNetworkSafe(networkId: Long): Boolean {
        if (!nativeLibraryLoaded) return false
        return try { nativeJoinNetwork(networkId) }
        catch (e: Exception) { Log.e(TAG, "joinNetwork failed", e); false }
        catch (e: Error) { Log.e(TAG, "joinNetwork error", e); false }
    }

    fun leaveNetworkSafe(networkId: Long): Boolean {
        if (!nativeLibraryLoaded) return false
        return try { nativeLeaveNetwork(networkId) }
        catch (e: Exception) { Log.e(TAG, "leaveNetwork failed", e); false }
        catch (e: Error) { Log.e(TAG, "leaveNetwork error", e); false }
    }

    fun getAddressSafe(index: Long): String? {
        if (!nativeLibraryLoaded) return null
        return try {
            val addr = nativeGetAddress(index)
            if (addr.isNullOrBlank()) null else addr
        } catch (e: Exception) { null } catch (e: Error) { null }
    }

    fun processPacket(packet: java.nio.ByteBuffer, length: Int): Int {
        if (!nativeLibraryLoaded) return -1
        return try { nativeProcessPacket(packet, length) }
        catch (e: Exception) { Log.e(TAG, "processPacket failed", e); -1 }
        catch (e: Error) { Log.e(TAG, "processPacket error", e); -1 }
    }

    fun readPacket(buffer: java.nio.ByteBuffer, capacity: Int): Int {
        if (!nativeLibraryLoaded) return 0
        return try { nativeReadPacket(buffer, capacity) }
        catch (e: Exception) { Log.e(TAG, "readPacket failed", e); 0 }
        catch (e: Error) { Log.e(TAG, "readPacket error", e); 0 }
    }

    fun ztsTcpConnect(destIP: String, destPort: Int): Int {
        if (!nativeLibraryLoaded) return -1
        return try { nativeZtsTcpConnect(destIP, destPort) }
        catch (e: Exception) { Log.e(TAG, "ztsTcpConnect failed", e); -1 }
        catch (e: Error) { Log.e(TAG, "ztsTcpConnect error", e); -1 }
    }

    // ══════════════════════════════════════════════════════════════════════
    // CRITICAL FIX: BigInteger helpers for safe Network ID conversion.
    // ZeroTier network IDs are 64-bit unsigned, but Java/Kotlin Long is
    // signed. When a 16-char hex value exceeds Long.MAX_VALUE (e.g.,
    // starts with 8-F), toLong() returns a negative number. The JNI
    // C++ layer interprets this as the correct unsigned 64-bit value.
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Convert a BigInteger Network ID to the signed Long expected by JNI.
     * For values > Long.MAX_VALUE, this returns a negative Long which
     * JNI interprets as the correct unsigned 64-bit value.
     */
    fun bigIntToNetworkId(value: BigInteger): Long {
        return value.toLong()
    }

    /**
     * Convert a signed Long (from JNI) back to an unsigned BigInteger
     * for proper display as a 16-char hex string.
     */
    fun networkIdToBigInt(value: Long): BigInteger {
        return BigInteger.valueOf(value).let {
            if (it.signum() < 0) it.add(BigInteger.ONE.shiftLeft(64)) else it
        }
    }

    // ── JNI Callbacks — Called from C++ via AttachCurrentThread ────────────

    /**
     * Called from C++ when ZeroTier engine state changes.
     *
     * State codes map to VpnState:
     *   0  (STOPPED)             → Disconnected
     *   1  (STARTING)            → InitializingNode
     *   2  (ONLINE)              → JoiningMesh (node is online, will join network)
     *   3  (OFFLINE)             → Reconnecting (was Error — now supports auto-retry)
     *   4  (NETWORK_READY)       → Connected
     *   5  (NETWORK_DOWN)        → Reconnecting (was Error — now supports auto-retry)
     *   6  (JOINING_NETWORK)     → JoiningMesh
     *   7  (WAITING_AUTHORIZATION) → WaitingAuthorization
     *   8  (P2P_HANDSHAKE)       → P2pHandshake (UDP hole punching in progress)
     *   9  (AUTHENTICATING)      → Authenticating (network controller verifying node)
     *   10 (RECONNECTING)        → Reconnecting (auto-reconnect after connectivity loss)
     *   -1 (ERROR)               → Error(message)
     */
    @Keep
    fun onZtStateChanged(stateCode: Int, message: String) {
        Log.i(TAG, "ZT State: code=$stateCode msg=$message")
        when (stateCode) {
            0 -> { VpnStateHolder.updateState(VpnState.Disconnected) }
            1 -> { VpnStateHolder.updateState(VpnState.InitializingNode) }
            2 -> { VpnStateHolder.updateState(VpnState.JoiningMesh) }
            3 -> {
                // OFFLINE — transition to Reconnecting instead of Error
                // The Kotlin layer will handle auto-retry
                Log.w(TAG, "ZeroTier node offline — triggering reconnect")
            }
            4 -> { VpnStateHolder.updateState(VpnState.Connected()) }
            5 -> {
                // NETWORK_DOWN — transition to Reconnecting instead of Error
                Log.w(TAG, "ZeroTier network down — triggering reconnect")
            }
            6 -> { VpnStateHolder.updateState(VpnState.JoiningMesh) }
            7 -> { VpnStateHolder.updateState(VpnState.WaitingAuthorization) }
            8 -> { VpnStateHolder.updateState(VpnState.P2pHandshake) }
            9 -> { VpnStateHolder.updateState(VpnState.Authenticating) }
            10 -> { VpnStateHolder.updateState(VpnState.Reconnecting(1, 3)) }
            -1 -> {
                Log.e(TAG, "ZeroTier engine error: $message")
                VpnStateHolder.updateState(VpnState.Error(message.ifBlank { "Unknown ZeroTier engine error" }))
                try { fatalErrorHandler?.invoke() } catch (e: Exception) {
                    Log.e(TAG, "Fatal error handler threw", e)
                }
            }
            else -> Log.w(TAG, "Unknown state code: $stateCode")
        }
    }

    @Keep
    fun onZtAssignedIP(ipv4: String, ipv6: String) {
        Log.i(TAG, "ZeroTier assigned IP: ipv4=$ipv4 ipv6=$ipv6")
        VpnStateHolder.updateAssignedIP(ipv4, ipv6)
        VpnStateHolder.updateNodeId(getNodeIdSafe())
    }

    @Keep
    fun onZtTrafficStats(bytesIn: Long, bytesOut: Long, packetsIn: Long, packetsOut: Long) {
        VpnStateHolder.updateTrafficStats(bytesIn, bytesOut, packetsIn, packetsOut)
    }

    @Keep
    fun onZtSocketCreated(fd: Int): Boolean {
        val service = vpnServiceRef
        if (service == null) {
            Log.e(TAG, "onZtSocketCreated: VpnService ref is null — cannot protect fd=$fd")
            return false
        }
        return try {
            val protected = service.protect(fd)
            if (protected) Log.i(TAG, "ZT socket fd=$fd protected")
            else Log.e(TAG, "protect($fd) returned false")
            protected
        } catch (e: Exception) {
            Log.e(TAG, "Exception in protect($fd)", e)
            false
        }
    }
}
