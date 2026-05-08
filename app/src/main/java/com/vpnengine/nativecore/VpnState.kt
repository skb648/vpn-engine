package com.vpnengine.nativecore

/**
 * VpnState — Sealed interface representing the VPN connection lifecycle.
 *
 * State progression follows the ZeroTier node lifecycle:
 *   Disconnected → InitializingNode → P2pHandshake → JoiningMesh →
 *   Authenticating → WaitingAuthorization → Connected
 *
 * On connectivity loss:
 *   Connected → Reconnecting → (auto-retry) → JoiningMesh → Connected
 *
 * The UI CANNOT show "Connected" unless the C++ engine confirms
 * ZTS_EVENT_NETWORK_READY_IP4 (state code 4). Zero dummy delays.
 * Every state transition is driven by a ZeroTier engine callback.
 */
sealed interface VpnState {

    /** VPN is disconnected. Idle state. */
    object Disconnected : VpnState

    /** General connecting state (fallback). Prefer specific stages for UI feedback. */
    object Connecting : VpnState

    /** ZeroTier node is starting up (zts_node_start called). */
    object InitializingNode : VpnState

    /** Node is online, UDP hole punching in progress (strict NAT/ISP). */
    object P2pHandshake : VpnState

    /** Node is online, joining the ZeroTier network (zts_net_join called). */
    object JoiningMesh : VpnState

    /** Network join sent, authenticating with network controller. */
    object Authenticating : VpnState

    /**
     * Network join requested, waiting for controller authorization.
     * This state persists until ZTS_EVENT_NETWORK_READY_IP4 fires,
     * which requires the network admin to authorize the node at
     * https://my.zerotier.com
     */
    object WaitingAuthorization : VpnState

    /**
     * VPN is fully connected. Only entered when C++ confirms
     * ZTS_EVENT_NETWORK_READY_IP4 AND the TUN bridge is active.
     *
     * @param sinceMs Epoch millis when connection was established.
     */
    data class Connected(val sinceMs: Long = System.currentTimeMillis()) : VpnState

    /**
     * Connection lost or failed — auto-reconnecting with retry.
     * This state is entered instead of Error when a transient
     * failure occurs (network drop, offline event, timeout).
     * The Kotlin layer will auto-retry before giving up.
     *
     * @param attempt Current retry attempt number (1-based).
     * @param maxAttempts Maximum number of retries before giving up.
     */
    data class Reconnecting(val attempt: Int, val maxAttempts: Int = 3) : VpnState

    /**
     * An error occurred after all retries exhausted. The engine is
     * stopped (or stopping). The user must disconnect and try again.
     *
     * @param message Human-readable error from C++ engine or Kotlin layer.
     */
    data class Error(val message: String) : VpnState
}
