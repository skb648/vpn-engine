/**
 * ZeroTierEngine.h — ZeroTier P2P Mesh VPN Engine for Android
 *
 * Architecture:
 *   ┌─────────────┐     ┌─────────────────┐     ┌──────────────────┐
 *   │ Android TUN │ ←→  │ ZeroTierEngine  │ ←→  │ ZeroTier Network │
 *   │  (tunFd)    │     │ (L3 ↔ L2 bridge)│     │  (P2P Mesh)      │
 *   └─────────────┘     └─────────────────┘     └──────────────────┘
 *
 * The ZeroTierEngine bridges the Android TUN interface (L3, IP packets)
 * with the ZeroTier virtual network (L2, Ethernet frames). It:
 *   1. Initializes a ZeroTier background node
 *   2. Auto-joins a specified Private Network ID
 *   3. Waits for ZT_EVENT_ONLINE confirmation
 *   4. Gets the assigned virtual IP address
 *   5. Bridges TUN <-> ZeroTier bidirectionally
 *   6. Reports state changes and traffic stats via callbacks
 *
 * CRITICAL JNI SAFETY:
 *   - All public methods are exception-safe
 *   - C++ exceptions NEVER cross the JNI boundary
 *   - Errors are reported via getLastError() and state callbacks
 *   - Network ID parsing validates 16-char hex strings
 *
 * BULLETPROOF LIFECYCLE (v5):
 *   - stopping_ flag prevents new operations during teardown
 *   - stop() uses coordinated shutdown with condition_variable
 *   - zts_node_free() only called after SDK threads have drained
 *   - Callbacks cleared before teardown to prevent use-after-free
 *   - All state transitions are atomic and race-condition free
 *   - stop() is fully re-entrant and idempotent
 *
 * Thread Safety:
 *   - ZeroTier's node runs on its own internal threads
 *   - TUN bridge runs on a dedicated std::thread
 *   - All shared state uses std::atomic or std::mutex
 *   - JNI callbacks use AttachCurrentThread pattern
 */

#pragma once

#include <string>
#include <atomic>
#include <mutex>
#include <thread>
#include <memory>
#include <functional>
#include <cstdint>
#include <vector>
#include <deque>
#include <condition_variable>

// ── ZeroTier SDK C API ──────────────────────────────────────────────────────
#include <ZeroTierSockets.h>

// ── Engine State Codes (reported to Kotlin via JNI callback) ────────────────
enum class ZtStateCode : int {
    STOPPED               = 0,   // Engine not started
    STARTING              = 1,   // Node initializing
    ONLINE                = 2,   // ZT_EVENT_NODE_ONLINE — node is online
    OFFLINE               = 3,   // ZT_EVENT_NODE_OFFLINE — lost connectivity
    NETWORK_READY         = 4,   // ZT_EVENT_NETWORK_READY_IP4 — have IP, can route
    NETWORK_DOWN          = 5,   // Network left or unavailable
    JOINING_NETWORK       = 6,   // Network join requested, waiting for auth
    WAITING_AUTHORIZATION = 7,   // Joined but waiting for controller approval
    P2P_HANDSHAKE         = 8,   // UDP hole punching in progress (strict NAT/ISP)
    AUTHENTICATING        = 9,   // Network controller authenticating the node
    RECONNECTING          = 10,  // Auto-reconnecting after connectivity loss
    ERROR                 = -1,  // Fatal error
};

// ── Engine Configuration ────────────────────────────────────────────────────

struct ZtConfig {
    std::string storagePath;
    uint64_t networkId;

    static constexpr int ZT_MTU = 1500;  // Standard MTU for compatibility
    static constexpr int ETH_HDR_SIZE = 14;
    static constexpr int MAX_FRAME_SIZE = ZT_MTU + ETH_HDR_SIZE + 4;
    static constexpr int TUN_READ_BUF = 65536;
    static constexpr int EPOLL_TIMEOUT_MS = 100;
    static constexpr int MAX_EPOLL_EVENTS = 16;
    static constexpr int STATS_INTERVAL_SEC = 5;
    static constexpr int MAX_CONSECUTIVE_ERRORS = 10;

    // ── Robustness Configuration ─────────────────────────────────────────
    static constexpr int NODE_STOP_DRAIN_MS = 3000;    // Wait for SDK threads to drain after zts_node_stop()
    static constexpr int BRIDGE_STOP_TIMEOUT_MS = 5000; // Max wait for bridge thread to join
    static constexpr int MAX_RETRY_ATTEMPTS = 5;        // Max auto-reconnect attempts
    static constexpr int RETRY_BACKOFF_BASE_MS = 3000;  // Exponential backoff base (2s, 4s, 8s)
};

// ── Callback Types ──────────────────────────────────────────────────────────

using ZtStateCallback   = std::function<void(int stateCode, const std::string& message)>;
using ZtIpCallback      = std::function<void(const std::string& ipv4, const std::string& ipv6)>;
using ZtStatsCallback   = std::function<void(uint64_t bytesIn, uint64_t bytesOut,
                                              uint64_t pktsIn, uint64_t pktsOut)>;

// ════════════════════════════════════════════════════════════════════════════
// ZeroTierEngine — Main engine class
// ════════════════════════════════════════════════════════════════════════════

class ZeroTierEngine {
public:
    ZeroTierEngine();
    ~ZeroTierEngine();

    // ── Lifecycle ───────────────────────────────────────────────────────

    /**
     * Start the ZeroTier node and auto-join the specified network.
     * EXCEPTION-SAFE: All internal operations are wrapped in try-catch.
     * On failure, returns false and sets lastError_.
     *
     * @param configPath  Directory for ZeroTier identity storage (MUST exist).
     * @param networkId   ZeroTier network ID to auto-join.
     * @return true if the node initialization was started successfully.
     */
    bool start(const std::string& configPath, uint64_t networkId);

    /**
     * Stop the ZeroTier node and the TUN bridge.
     * BULLETPROOF: Uses coordinated shutdown to prevent SIGABRT.
     *   1. Sets stopping_ flag to block new operations
     *   2. Clears callbacks to prevent use-after-free
     *   3. Stops TUN bridge with thread joining
     *   4. Leaves network
     *   5. Invalidates global pointer before zts_node_stop()
     *   6. Calls zts_node_stop() and waits for SDK threads to drain
     *   7. Only then calls zts_node_free()
     *   8. Fully re-entrant and idempotent
     */
    void stop();

    /** Check if the ZeroTier node is online. */
    bool isOnline() const;

    /** Check if the engine is running (node started, not necessarily online). */
    bool isRunning() const;

    /** Check if the engine is currently stopping. */
    bool isStopping() const;

    /** Get the current state code. Thread-safe. */
    ZtStateCode getCurrentState() const;

    /** Get the last error message. Thread-safe. */
    std::string getLastError() const;

    // ── Network Management ──────────────────────────────────────────────

    /** Join a ZeroTier network. */
    bool joinNetwork(uint64_t networkId);

    /** Leave a ZeroTier network. */
    bool leaveNetwork(uint64_t networkId);

    /** Get the assigned IPv4 address for the current network. */
    std::string getAssignedIPv4() const;

    /** Get the assigned IPv6 address for the current network. */
    std::string getAssignedIPv6() const;

    /** Get the ZeroTier node ID (10-digit hex). */
    uint64_t getNodeId() const;

    /** Get the currently joined network ID. */
    uint64_t getNetworkId() const;

    // ── TUN Bridge ──────────────────────────────────────────────────────

    /**
     * Start the TUN <-> ZeroTier bridge.
     * @param tunFd  File descriptor from VpnService.Builder.establish().
     * @return true if the bridge started successfully.
     */
    bool startTunBridge(int tunFd);

    /** Stop the TUN bridge thread. */
    void stopTunBridge();

    // ── Callbacks ───────────────────────────────────────────────────────

    void setStateCallback(ZtStateCallback cb);
    void setIpCallback(ZtIpCallback cb);
    void setStatsCallback(ZtStatsCallback cb);

    // ── Socket Protection (called from Kotlin via JNI) ──────────────────

    using SocketProtectCallback = std::function<bool(int fd)>;
    void setSocketProtectCallback(SocketProtectCallback cb);

private:
    // ── ZeroTier Event Callback (static, called from ZT internal thread) ─
    static void onZtEvent(void* msg);

    // ── TUN Bridge Thread ───────────────────────────────────────────────
    void tunBridgeLoop();       // Outer try-catch wrapper
    void tunBridgeLoopInner();  // Actual implementation

    // ── Internal helpers ────────────────────────────────────────────────
    void notifyState(ZtStateCode code, const std::string& msg);
    void notifyIp(const std::string& ipv4, const std::string& ipv6);
    void notifyStats();
    void setError(const std::string& error);

    /**
     * Clear all callbacks. Called during teardown to prevent
     * use-after-free when ZeroTier SDK threads fire late callbacks.
     */
    void clearCallbacks();

    /**
     * Force-stop the engine without calling zts_node_free().
     * Used as a last resort when normal stop() fails.
     */
    void forceStop();

    // ── State ───────────────────────────────────────────────────────────
    std::atomic<bool>       running_{false};
    std::atomic<bool>       online_{false};
    std::atomic<bool>       networkReady_{false};
    std::atomic<bool>       bridgeRunning_{false};
    std::atomic<bool>       stopping_{false};           // BULLETPROOF: prevents new ops during teardown
    std::atomic<ZtStateCode> currentState_{ZtStateCode::STOPPED};

    int                     tunFd_{-1};
    uint64_t                networkId_{0};
    std::atomic<uint64_t>   nodeId_{0};

    std::string             assignedIPv4_;
    std::string             assignedIPv6_;
    mutable std::mutex      stateMutex_;

    // ── Thread Coordination ─────────────────────────────────────────────
    std::unique_ptr<std::thread> bridgeThread_;
    std::mutex              stopMutex_;                  // Protects the stop sequence
    std::condition_variable stopCv_;                     // Signaled when bridge thread exits

    // ── Callbacks ───────────────────────────────────────────────────────
    ZtStateCallback         stateCallback_;
    ZtIpCallback            ipCallback_;
    ZtStatsCallback         statsCallback_;
    SocketProtectCallback   socketProtectCallback_;
    mutable std::mutex      callbackMutex_;

    // ── Traffic Stats ───────────────────────────────────────────────────
    std::atomic<uint64_t>   bytesIn_{0};
    std::atomic<uint64_t>   bytesOut_{0};
    std::atomic<uint64_t>   packetsIn_{0};
    std::atomic<uint64_t>   packetsOut_{0};
    std::atomic<uint64_t>   packetsDropped_{0};

    // ── Error State ─────────────────────────────────────────────────────
    mutable std::mutex      errorMutex_;
    std::string             lastError_;
};
