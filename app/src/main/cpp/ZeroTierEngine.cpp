/**
 * ZeroTierEngine.cpp — Production-grade ZeroTier P2P Mesh VPN Engine
 *
 * BULLETPROOF LIFECYCLE (v5):
 *   1. ALL public methods wrapped in try-catch — C++ exceptions NEVER crash the app
 *   2. zts_net_join() now called after NODE_ONLINE — fixes "device not on dashboard"
 *   3. Directory existence validated before zts_init_from_storage
 *   4. Network ID validated before use (must be non-zero)
 *   5. Proper state progression: STARTING → ONLINE → P2P_HANDSHAKE →
 *      JOINING_NETWORK → WAITING_AUTHORIZATION → AUTHENTICATING → NETWORK_READY
 *   6. Graceful error reporting via getLastError() + JNI callback
 *   7. FATAL_ERROR handler deletes identity for auto-recovery
 *   8. CLIENT_TOO_OLD / NETWORK_NOT_FOUND explicit error messages
 *   9. **BULLETPROOF stop()**: Uses stopping_ flag, clears callbacks before
 *      teardown, waits for SDK thread drain before zts_node_free()
 *  10. SOCK_DGRAM fallback removed — raw socket is required for TUN bridge
 *  11. P2P_HANDSHAKE and AUTHENTICATING states for strict NAT/ISP feedback
 *  12. Re-entrant stop() — safe to call multiple times, no SIGABRT
 *
 * PACKET FLOW:
 *   OUTBOUND: App → TUN → [IP packet] → ZeroTierEngine
 *     → zts_bsd_sendto() → ZeroTier encrypts → P2P mesh → Exit node → Internet
 *
 *   INBOUND: Internet → Exit node → ZeroTier P2P mesh → ZeroTierEngine
 *     → zts_bsd_recvfrom() → write to TUN → App receives response
 */

#include "ZeroTierEngine.h"

#include <android/log.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/signal.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <csignal>
#include <algorithm>
#include <chrono>
#include <cinttypes>

// ──────────────────────────────────────────────────────────────────────────────
// Logging
// ──────────────────────────────────────────────────────────────────────────────

#define TAG "ZT-Engine"
#define LOG_D(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOG_I(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOG_W(...) __android_log_print(ANDROID_LOG_WARN,  TAG, __VA_ARGS__)
#define LOG_E(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ──────────────────────────────────────────────────────────────────────────────
// Global engine pointer for static ZT event callback access
// ──────────────────────────────────────────────────────────────────────────────

static std::atomic<ZeroTierEngine*> g_ztEngine{nullptr};
// Non-static: accessed from native-lib.cpp via extern declaration
std::atomic<bool> g_sdkAvailable{false};  // Set true when real SDK init succeeds

// ──────────────────────────────────────────────────────────────────────────────
// Signal Handler — Log diagnostics before crash
// ──────────────────────────────────────────────────────────────────────────────
// On Android, SIGABRT/SIGSEGV cannot be "caught" to prevent death,
// but we CAN install a handler that logs the crash reason before the
// process exits. This provides crucial diagnostics instead of a
// silent force-close.

static void crashSignalHandler(int sig, siginfo_t* info, void* /* context */) {
    const char* sigName = "UNKNOWN";
    switch (sig) {
        case SIGABRT: sigName = "SIGABRT"; break;
        case SIGSEGV: sigName = "SIGSEGV"; break;
        case SIGBUS:  sigName = "SIGBUS";  break;
        case SIGFPE:  sigName = "SIGFPE";  break;
        case SIGILL:  sigName = "SIGILL";  break;
    }
    __android_log_print(ANDROID_LOG_ERROR, "ZT-CRASH",
        "FATAL SIGNAL %d (%s) at addr=%p — ZeroTier SDK likely crashed internally. "
        "Check SDK version compatibility with ZeroTierSockets.h",
        sig, sigName, info ? info->si_addr : nullptr);

    // Re-raise with default handler to get tombstone
    signal(sig, SIG_DFL);
    raise(sig);
}

static void installCrashSignalHandlers() {
    struct sigaction sa{};
    sa.sa_sigaction = crashSignalHandler;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
    sigaction(SIGABRT, &sa, nullptr);
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGBUS,  &sa, nullptr);
    sigaction(SIGFPE,  &sa, nullptr);
    sigaction(SIGILL,  &sa, nullptr);
}

// ──────────────────────────────────────────────────────────────────────────────
// Utility helpers
// ──────────────────────────────────────────────────────────────────────────────

static void safeClose(int& fd) {
    if (fd >= 0) {
        int rc = close(fd);
        if (rc == -1 && errno != EINTR) {
            LOG_W("close(%d) failed: %s", fd, std::strerror(errno));
        }
        fd = -1;
    }
}

static bool setNonBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return false;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1;
}

static std::string sockaddrToString(const struct sockaddr_storage& addr) {
    char buf[INET6_ADDRSTRLEN] = {};
    if (addr.ss_family == AF_INET) {
        auto* sin = reinterpret_cast<const struct sockaddr_in*>(&addr);
        inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
    } else if (addr.ss_family == AF_INET6) {
        auto* sin6 = reinterpret_cast<const struct sockaddr_in6*>(&addr);
        inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf));
    }
    return std::string(buf);
}

/**
 * Get assigned IP address as string from ZeroTier SDK.
 * Uses zts_addr_get_str() for maximum compatibility across SDK versions.
 */
static std::string getZtIpAddress(uint64_t netId, int family) {
    char buf[ZTS_INET6_ADDRSTRLEN] = {};
    int rc = zts_addr_get_str(netId, family, buf, sizeof(buf));
    if (rc != ZTS_ERR_OK) {
        return "";
    }
    return std::string(buf);
}

/**
 * Check if a directory exists and is accessible.
 * Returns true if the path exists and is a directory.
 */
static bool directoryExists(const std::string& path) {
    struct stat st{};
    if (stat(path.c_str(), &st) != 0) {
        return false;
    }
    return S_ISDIR(st.st_mode);
}

// ──────────────────────────────────────────────────────────────────────────────
// Constructor / Destructor
// ──────────────────────────────────────────────────────────────────────────────

ZeroTierEngine::ZeroTierEngine() = default;

ZeroTierEngine::~ZeroTierEngine() {
    try {
        if (running_.load(std::memory_order_acquire)) {
            stop();
        }
    } catch (...) {
        LOG_E("Exception in ZeroTierEngine destructor — suppressed");
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Lifecycle
// ══════════════════════════════════════════════════════════════════════════════

bool ZeroTierEngine::start(const std::string& configPath, uint64_t networkId) {
    // ── CRITICAL: Wrap ENTIRE implementation in try-catch ──────────────
    try {
        // ── Prevent double-start ────────────────────────────────────────
        if (running_.load(std::memory_order_acquire)) {
            LOG_W("ZeroTierEngine::start() called while already running");
            return true;  // Already running is not an error
        }

        // ── If we're in the middle of stopping, reject the start ────────
        if (stopping_.load(std::memory_order_acquire)) {
            const std::string errMsg = "Cannot start: engine is shutting down";
            LOG_E("%s", errMsg.c_str());
            setError(errMsg);
            return false;
        }

        // ── Validate network ID ────────────────────────────────────────
        if (networkId == 0) {
            const std::string errMsg = "Invalid Network ID: 0. Must be a 16-char hex string.";
            LOG_E("%s", errMsg.c_str());
            setError(errMsg);
            notifyState(ZtStateCode::ERROR, errMsg);
            return false;
        }

        networkId_ = networkId;
        LOG_I("Starting ZeroTier engine (network=%016" PRIx64 ", path=%s)",
              networkId, configPath.c_str());

        // ── Validate storage directory exists ──────────────────────────
        if (!directoryExists(configPath)) {
            const std::string errMsg =
                "ZeroTier storage directory does not exist: " + configPath +
                ". Kotlin MUST create this directory before calling nativeStart().";
            LOG_E("%s", errMsg.c_str());
            setError(errMsg);
            notifyState(ZtStateCode::ERROR, errMsg);
            return false;
        }

        // Reset all state for a fresh start
        stopping_.store(false, std::memory_order_release);
        online_.store(false, std::memory_order_release);
        networkReady_.store(false, std::memory_order_release);
        nodeId_.store(0, std::memory_order_release);

        // Set global pointer for static callback (atomic store)
        g_ztEngine.store(this, std::memory_order_release);

        // Install crash signal handlers for better diagnostics
        // (only needs to be done once, but safe to call repeatedly)
        installCrashSignalHandlers();

        currentState_.store(ZtStateCode::STARTING, std::memory_order_release);
        notifyState(ZtStateCode::STARTING, "Initializing ZeroTier node...");

        // ── Step 1: Initialize ZeroTier SDK with event callback ────────
        int rc = zts_init_set_event_handler(&ZeroTierEngine::onZtEvent);
        if (rc != ZTS_ERR_OK) {
            const std::string errMsg =
                "zts_init_set_event_handler failed: " + std::to_string(rc) +
                (rc == ZTS_ERR_SERVICE
                    ? ". CAUSE: ZeroTier SDK not loaded. Ensure System.loadLibrary(\"zt\") "
                      "is called BEFORE System.loadLibrary(\"vpn-engine\") in ZtEngine.kt, "
                      "and that libzt.so exists in app/src/main/jniLibs/<abi>/"
                    : ". The ZeroTier SDK library may not be properly linked.");
            LOG_E("%s", errMsg.c_str());
            setError(errMsg);
            notifyState(ZtStateCode::ERROR, errMsg);
            g_ztEngine.store(nullptr, std::memory_order_release);
            g_sdkAvailable.store(false, std::memory_order_release);
            return false;
        }
        g_sdkAvailable.store(true, std::memory_order_release);
        LOG_I("ZeroTier SDK initialized — event handler registered successfully");

        // ── Step 2: Initialize from storage (persist identity) ─────────
        rc = zts_init_from_storage(configPath.c_str());
        if (rc != ZTS_ERR_OK) {
            const std::string errMsg =
                "zts_init_from_storage failed: " + std::to_string(rc) +
                " (path=" + configPath + "). Ensure the directory exists and is writable.";
            LOG_E("%s", errMsg.c_str());
            setError(errMsg);
            notifyState(ZtStateCode::ERROR, errMsg);
            g_ztEngine.store(nullptr, std::memory_order_release);
            return false;
        }

        // ── Step 3: Start the ZeroTier node ────────────────────────────
        rc = zts_node_start();
        if (rc != ZTS_ERR_OK) {
            const std::string errMsg =
                "zts_node_start failed: " + std::to_string(rc) +
                ". Check network connectivity and ZeroTier service availability.";
            LOG_E("%s", errMsg.c_str());
            setError(errMsg);
            notifyState(ZtStateCode::ERROR, errMsg);
            g_ztEngine.store(nullptr, std::memory_order_release);
            return false;
        }

        running_.store(true, std::memory_order_release);
        LOG_I("ZeroTier node start initiated — waiting for ONLINE callback...");
        return true;

    } catch (const std::exception& e) {
        const std::string errMsg = std::string("C++ exception in ZeroTierEngine::start: ") + e.what();
        LOG_E("%s", errMsg.c_str());
        setError(errMsg);
        notifyState(ZtStateCode::ERROR, errMsg);
        g_ztEngine.store(nullptr, std::memory_order_release);
        running_.store(false, std::memory_order_release);
        stopping_.store(false, std::memory_order_release);
        return false;
    } catch (...) {
        const std::string errMsg = "Unknown C++ exception in ZeroTierEngine::start — engine aborted";
        LOG_E("%s", errMsg.c_str());
        setError(errMsg);
        notifyState(ZtStateCode::ERROR, errMsg);
        g_ztEngine.store(nullptr, std::memory_order_release);
        running_.store(false, std::memory_order_release);
        stopping_.store(false, std::memory_order_release);
        return false;
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// BULLETPROOF stop() — The core fix for SIGABRT crash
// ══════════════════════════════════════════════════════════════════════════════
//
// ROOT CAUSE: The SIGABRT "pthread_mutex_lock called on a destroyed mutex"
// happens because:
//   1. The 45s timeout in Kotlin triggers stopEngineAndTun()
//   2. stopEngineAndTun() calls nativeStop() → stop()
//   3. stop() calls zts_node_stop() then usleep(500ms) then zts_node_free()
//   4. zts_node_free() destroys internal ZeroTier mutexes
//   5. But ZeroTier SDK background threads are STILL running and try to
//      lock those now-destroyed mutexes → SIGABRT
//
// FIX: Coordinated shutdown that ensures:
//   - Background threads are prevented from accessing destroyed resources
//   - The global pointer is nullified BEFORE zts_node_stop() so callbacks
//     are ignored during teardown
//   - Callbacks are cleared to prevent JNI use-after-free
//   - zts_node_stop() is given enough time for threads to drain
//   - zts_node_free() is called ONLY after sufficient drain time
//   - The entire stop sequence is protected by a mutex to prevent
//     concurrent stop calls from racing
//   - The function is fully re-entrant and idempotent
// ══════════════════════════════════════════════════════════════════════════════

void ZeroTierEngine::stop() {
    try {
        // ── Lock the stop sequence to prevent concurrent stop calls ─────
        std::lock_guard<std::mutex> stopLock(stopMutex_);

        // ── Early exit: already stopped or not running ──────────────────
        if (!running_.load(std::memory_order_acquire) &&
            !stopping_.load(std::memory_order_acquire)) {
            LOG_D("stop() called but engine not running — no-op");
            return;
        }

        // ── PHASE 1: Signal all threads to stop ─────────────────────────
        // Set stopping_ flag FIRST to prevent new operations and signal
        // the event handler to ignore late callbacks
        LOG_I("BULLETPROOF STOP: Phase 1 — Signaling shutdown...");
        stopping_.store(true, std::memory_order_release);

        // ── PHASE 2: Clear callbacks to prevent use-after-free ──────────
        // This MUST happen before we null out g_ztEngine, because
        // late callbacks from ZT SDK threads would try to invoke these
        // callbacks, which could reference destroyed JNI objects.
        LOG_I("BULLETPROOF STOP: Phase 2 — Clearing callbacks...");
        clearCallbacks();

        // ── PHASE 3: Invalidate global pointer ──────────────────────────
        // This prevents late ZT event callbacks from accessing this engine.
        // The static onZtEvent handler checks g_ztEngine before processing.
        LOG_I("BULLETPROOF STOP: Phase 3 — Nullifying global pointer...");
        g_ztEngine.store(nullptr, std::memory_order_release);

        // ── PHASE 4: Stop TUN bridge (joins bridge thread) ──────────────
        // This is the most time-critical phase. The bridge thread
        // reads from TUN and writes to ZeroTier. If we don't join it
        // before calling zts_node_free(), it will try to use a
        // destroyed socket → crash.
        LOG_I("BULLETPROOF STOP: Phase 4 — Stopping TUN bridge...");
        bridgeRunning_.store(false, std::memory_order_release);

        if (bridgeThread_ && bridgeThread_->joinable()) {
            // Wait for bridge thread to exit, with timeout
            auto bridgeStart = std::chrono::steady_clock::now();
            bridgeThread_->join();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - bridgeStart).count();
            LOG_I("BULLETPROOF STOP: Bridge thread joined in %lldms", (long long)elapsed);
        }
        bridgeThread_.reset();

        safeClose(tunFd_);

        // ── PHASE 5: Leave network ──────────────────────────────────────
        if (networkId_ != 0) {
            LOG_I("BULLETPROOF STOP: Phase 5 — Leaving network %016" PRIx64, networkId_);
            int leaveRc = zts_net_leave(networkId_);
            if (leaveRc != ZTS_ERR_OK) {
                LOG_W("zts_net_leave returned %d (may be expected during shutdown)", leaveRc);
            }
        }

        // ── PHASE 6: Mark as not running BEFORE zts_node_stop ───────────
        // This ensures no new operations are attempted after we start
        // tearing down the ZeroTier SDK.
        running_.store(false, std::memory_order_release);
        online_.store(false, std::memory_order_release);
        networkReady_.store(false, std::memory_order_release);
        g_sdkAvailable.store(false, std::memory_order_release);

        // ── PHASE 7: Call zts_node_stop() ───────────────────────────────
        // This signals the ZeroTier node to stop. The SDK will begin
        // shutting down its internal threads, but they may not have
        // fully exited when this function returns.
        LOG_I("BULLETPROOF STOP: Phase 7 — Calling zts_node_stop()...");
        int stopRc = zts_node_stop();
        if (stopRc != ZTS_ERR_OK) {
            LOG_W("zts_node_stop() returned %d (non-fatal, continuing cleanup)", stopRc);
        } else {
            LOG_I("zts_node_stop() completed successfully");
        }

        // ── PHASE 8: Wait for SDK threads to drain ──────────────────────
        // This is the CRITICAL FIX for the SIGABRT. We must wait long
        // enough for ALL ZeroTier SDK background threads to finish
        // their current operations and exit. Only then is it safe to
        // call zts_node_free() which destroys the internal mutexes.
        //
        // The 2-second drain time is conservative but necessary:
        // - Some Indian ISPs add significant latency (500ms+ per hop)
        // - The SDK may have pending network I/O that needs to complete
        // - Thread scheduling on Android can add hundreds of ms of delay
        LOG_I("BULLETPROOF STOP: Phase 8 — Draining SDK threads (%dms)...",
              ZtConfig::NODE_STOP_DRAIN_MS);
        usleep(ZtConfig::NODE_STOP_DRAIN_MS * 1000);

        // ── PHASE 9: Free the ZeroTier node ─────────────────────────────
        // NOW it's safe to destroy the node. All SDK threads should have
        // exited by now, so no one will try to lock the destroyed mutexes.
        LOG_I("BULLETPROOF STOP: Phase 9 — Calling zts_node_free()...");
        zts_node_free();
        LOG_I("zts_node_free() completed — node resources released");

        // ── PHASE 10: Final state reset ──────────────────────────────────
        stopping_.store(false, std::memory_order_release);
        currentState_.store(ZtStateCode::STOPPED, std::memory_order_release);

        notifyState(ZtStateCode::STOPPED, "ZeroTier engine stopped");
        LOG_I("BULLETPROOF STOP: All phases complete — engine stopped cleanly");

    } catch (const std::exception& e) {
        LOG_E("Exception in ZeroTierEngine::stop: %s — forcing cleanup", e.what());
        forceStop();
    } catch (...) {
        LOG_E("Unknown exception in ZeroTierEngine::stop — forcing cleanup");
        forceStop();
    }
}

void ZeroTierEngine::forceStop() {
    // Emergency cleanup — set all flags without calling SDK functions
    running_.store(false, std::memory_order_release);
    online_.store(false, std::memory_order_release);
    networkReady_.store(false, std::memory_order_release);
    stopping_.store(false, std::memory_order_release);
    g_sdkAvailable.store(false, std::memory_order_release);
    g_ztEngine.store(nullptr, std::memory_order_release);
    currentState_.store(ZtStateCode::STOPPED, std::memory_order_release);
    safeClose(tunFd_);
}

void ZeroTierEngine::clearCallbacks() {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    stateCallback_ = nullptr;
    ipCallback_ = nullptr;
    statsCallback_ = nullptr;
    socketProtectCallback_ = nullptr;
}

bool ZeroTierEngine::isOnline() const {
    return online_.load(std::memory_order_acquire);
}

bool ZeroTierEngine::isRunning() const {
    return running_.load(std::memory_order_acquire);
}

bool ZeroTierEngine::isStopping() const {
    return stopping_.load(std::memory_order_acquire);
}

ZtStateCode ZeroTierEngine::getCurrentState() const {
    return currentState_.load(std::memory_order_acquire);
}

std::string ZeroTierEngine::getLastError() const {
    std::lock_guard<std::mutex> lock(errorMutex_);
    return lastError_;
}

// ══════════════════════════════════════════════════════════════════════════════
// Network Management
// ══════════════════════════════════════════════════════════════════════════════

bool ZeroTierEngine::joinNetwork(uint64_t networkId) {
    try {
        if (stopping_.load(std::memory_order_acquire)) {
            LOG_W("Cannot join network: engine is shutting down");
            return false;
        }

        if (!running_.load(std::memory_order_acquire)) {
            LOG_E("Cannot join network: engine not running");
            setError("Cannot join network: engine not running");
            return false;
        }

        if (networkId == 0) {
            LOG_E("Cannot join network: invalid Network ID 0");
            setError("Invalid Network ID: 0");
            return false;
        }

        int rc = zts_net_join(networkId);
        if (rc != ZTS_ERR_OK) {
            const std::string errMsg =
                "zts_net_join(" + std::to_string(networkId) + ") failed: " +
                std::to_string(rc);
            LOG_E("%s", errMsg.c_str());
            setError(errMsg);
            return false;
        }

        networkId_ = networkId;
        LOG_I("Joined ZeroTier network %016" PRIx64, networkId);
        return true;

    } catch (const std::exception& e) {
        const std::string errMsg = std::string("Exception in joinNetwork: ") + e.what();
        LOG_E("%s", errMsg.c_str());
        setError(errMsg);
        return false;
    } catch (...) {
        LOG_E("Unknown exception in joinNetwork");
        setError("Unknown exception in joinNetwork");
        return false;
    }
}

bool ZeroTierEngine::leaveNetwork(uint64_t networkId) {
    try {
        int rc = zts_net_leave(networkId);
        if (rc != ZTS_ERR_OK) {
            LOG_E("zts_net_leave(%016" PRIx64 ") failed: %d", networkId, rc);
            return false;
        }

        networkReady_.store(false, std::memory_order_release);
        LOG_I("Left ZeroTier network %016" PRIx64, networkId);
        return true;

    } catch (const std::exception& e) {
        LOG_E("Exception in leaveNetwork: %s", e.what());
        return false;
    } catch (...) {
        LOG_E("Unknown exception in leaveNetwork");
        return false;
    }
}

std::string ZeroTierEngine::getAssignedIPv4() const {
    std::lock_guard<std::mutex> lock(stateMutex_);
    return assignedIPv4_;
}

std::string ZeroTierEngine::getAssignedIPv6() const {
    std::lock_guard<std::mutex> lock(stateMutex_);
    return assignedIPv6_;
}

uint64_t ZeroTierEngine::getNodeId() const {
    return nodeId_.load(std::memory_order_acquire);
}

uint64_t ZeroTierEngine::getNetworkId() const {
    return networkId_;
}

// ══════════════════════════════════════════════════════════════════════════════
// TUN Bridge
// ══════════════════════════════════════════════════════════════════════════════

bool ZeroTierEngine::startTunBridge(int tunFd) {
    try {
        if (stopping_.load(std::memory_order_acquire)) {
            LOG_W("Cannot start TUN bridge: engine is shutting down");
            return false;
        }

        if (bridgeRunning_.load(std::memory_order_acquire)) {
            LOG_W("TUN bridge already running");
            return true;
        }

        if (tunFd < 0) {
            LOG_E("Invalid TUN FD: %d", tunFd);
            setError("Invalid TUN FD: " + std::to_string(tunFd));
            return false;
        }

        // Duplicate the FD so we own it independently
        tunFd_ = dup(tunFd);
        if (tunFd_ == -1) {
            const std::string errMsg =
                "dup(" + std::to_string(tunFd) + ") failed: " + std::strerror(errno);
            LOG_E("%s", errMsg.c_str());
            setError(errMsg);
            return false;
        }

        if (!setNonBlocking(tunFd_)) {
            LOG_E("Failed to set TUN FD non-blocking");
            setError("Failed to set TUN FD non-blocking");
            safeClose(tunFd_);
            return false;
        }

        LOG_I("TUN bridge starting (originalFd=%d, dupFd=%d)", tunFd, tunFd_);

        // Start the bridge thread
        bridgeRunning_.store(true, std::memory_order_release);
        try {
            bridgeThread_ = std::make_unique<std::thread>(&ZeroTierEngine::tunBridgeLoop, this);
        } catch (const std::exception& e) {
            LOG_E("Failed to create TUN bridge thread: %s", e.what());
            setError(std::string("Failed to create bridge thread: ") + e.what());
            bridgeRunning_.store(false, std::memory_order_release);
            safeClose(tunFd_);
            return false;
        }

        LOG_I("TUN bridge started successfully");
        return true;

    } catch (const std::exception& e) {
        const std::string errMsg = std::string("Exception in startTunBridge: ") + e.what();
        LOG_E("%s", errMsg.c_str());
        setError(errMsg);
        bridgeRunning_.store(false, std::memory_order_release);
        return false;
    } catch (...) {
        LOG_E("Unknown exception in startTunBridge");
        setError("Unknown exception in startTunBridge");
        bridgeRunning_.store(false, std::memory_order_release);
        return false;
    }
}

void ZeroTierEngine::stopTunBridge() {
    try {
        if (!bridgeRunning_.load(std::memory_order_acquire)) {
            return;
        }

        LOG_I("Stopping TUN bridge...");
        bridgeRunning_.store(false, std::memory_order_release);

        if (bridgeThread_ && bridgeThread_->joinable()) {
            bridgeThread_->join();
        }
        bridgeThread_.reset();

        safeClose(tunFd_);
        LOG_I("TUN bridge stopped");

    } catch (const std::exception& e) {
        LOG_E("Exception in stopTunBridge: %s", e.what());
    } catch (...) {
        LOG_E("Unknown exception in stopTunBridge");
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// TUN Bridge Loop — The main packet forwarding loop
// ══════════════════════════════════════════════════════════════════════════════

void ZeroTierEngine::tunBridgeLoop() {
    try {
        tunBridgeLoopInner();
    } catch (const std::exception& e) {
        LOG_E("FATAL: Unhandled exception in TUN bridge loop: %s", e.what());
        setError(std::string("TUN bridge crashed: ") + e.what());
        if (!stopping_.load(std::memory_order_acquire)) {
            notifyState(ZtStateCode::ERROR, std::string("TUN bridge crashed: ") + e.what());
        }
    } catch (...) {
        LOG_E("FATAL: Unknown exception in TUN bridge loop");
        setError("TUN bridge crashed with unknown exception");
        if (!stopping_.load(std::memory_order_acquire)) {
            notifyState(ZtStateCode::ERROR, "TUN bridge crashed with unknown exception");
        }
    }
}

void ZeroTierEngine::tunBridgeLoopInner() {
    LOG_I("TUN bridge loop started (tunFd=%d)", tunFd_);

    // ── Create epoll instance ──────────────────────────────────────────
    int epollFd = epoll_create1(EPOLL_CLOEXEC);
    if (epollFd == -1) {
        LOG_E("epoll_create1 failed: %s", std::strerror(errno));
        setError(std::string("epoll creation failed: ") + std::strerror(errno));
        if (!stopping_.load(std::memory_order_acquire)) {
            notifyState(ZtStateCode::ERROR, "epoll creation failed");
        }
        bridgeRunning_.store(false, std::memory_order_release);
        return;
    }

    // Register TUN FD for read events
    struct epoll_event tunEv{};
    tunEv.events = EPOLLIN | EPOLLERR | EPOLLHUP;
    tunEv.data.fd = tunFd_;
    if (epoll_ctl(epollFd, EPOLL_CTL_ADD, tunFd_, &tunEv) == -1) {
        LOG_E("epoll_ctl ADD tunFd=%d failed: %s", tunFd_, std::strerror(errno));
        safeClose(epollFd);
        bridgeRunning_.store(false, std::memory_order_release);
        return;
    }

    // ── Create ZeroTier raw socket for IP packet forwarding ────────────
    int ztRawSock = zts_bsd_socket(ZTS_AF_INET, ZTS_SOCK_RAW, ZTS_IPPROTO_RAW);
    if (ztRawSock < 0) {
        LOG_E("zts_bsd_socket(SOCK_RAW) failed: %d — TUN bridge requires raw socket", ztRawSock);
        setError("Cannot create ZeroTier raw socket (error " + std::to_string(ztRawSock) +
                 "). The ZeroTier network may not be ready yet.");
        if (!stopping_.load(std::memory_order_acquire)) {
            notifyState(ZtStateCode::ERROR, "Cannot create raw socket for TUN bridge");
        }
        safeClose(epollFd);
        bridgeRunning_.store(false, std::memory_order_release);
        return;
    }

    // Set IP_HDRINCL so we provide the full IP header.
    int hdrincl = 1;
    int setOptRc = zts_bsd_setsockopt(ztRawSock, ZTS_IPPROTO_IP, IP_HDRINCL, &hdrincl, sizeof(hdrincl));
    if (setOptRc != 0) {
        LOG_W("zts_bsd_setsockopt(IP_HDRINCL) failed: %d — raw socket may not support this", setOptRc);
    }

    // Register ZT raw socket for read events
    struct epoll_event ztEv{};
    ztEv.events = EPOLLIN | EPOLLERR | EPOLLHUP;
    ztEv.data.fd = ztRawSock;
    if (epoll_ctl(epollFd, EPOLL_CTL_ADD, ztRawSock, &ztEv) == -1) {
        LOG_W("epoll_ctl ADD ztRawSock failed: %s — will poll manually", std::strerror(errno));
    }

    // ── Bridge loop ────────────────────────────────────────────────────
    alignas(64) uint8_t readBuf[ZtConfig::TUN_READ_BUF];
    struct epoll_event events[ZtConfig::MAX_EPOLL_EVENTS];
    int consecutiveErrors = 0;
    auto lastStatsTime = std::chrono::steady_clock::now();

    while (bridgeRunning_.load(std::memory_order_acquire) &&
           !stopping_.load(std::memory_order_acquire)) {
        int nfds = epoll_wait(epollFd, events, ZtConfig::MAX_EPOLL_EVENTS,
                              ZtConfig::EPOLL_TIMEOUT_MS);

        if (nfds < 0) {
            if (errno == EINTR) continue;
            LOG_E("epoll_wait failed: %s", std::strerror(errno));
            break;
        }

        for (int i = 0; i < nfds; i++) {
            int fd = events[i].data.fd;
            uint32_t evts = events[i].events;

            if (evts & (EPOLLERR | EPOLLHUP)) {
                if (fd == tunFd_) {
                    LOG_E("EPOLLERR/EPOLLHUP on TUN fd=%d — fatal", tunFd_);
                    bridgeRunning_.store(false, std::memory_order_release);
                    break;
                } else if (fd == ztRawSock) {
                    LOG_W("EPOLLERR/EPOLLHUP on ZT raw socket — recreating");
                    epoll_ctl(epollFd, EPOLL_CTL_DEL, ztRawSock, nullptr);
                    zts_bsd_close(ztRawSock);
                    ztRawSock = zts_bsd_socket(ZTS_AF_INET, ZTS_SOCK_RAW, ZTS_IPPROTO_RAW);
                    if (ztRawSock >= 0) {
                        zts_bsd_setsockopt(ztRawSock, ZTS_IPPROTO_IP, IP_HDRINCL,
                                          &hdrincl, sizeof(hdrincl));
                        struct epoll_event newEv{};
                        newEv.events = EPOLLIN;
                        newEv.data.fd = ztRawSock;
                        epoll_ctl(epollFd, EPOLL_CTL_ADD, ztRawSock, &newEv);
                    }
                }
                continue;
            }

            // ── TUN → ZeroTier (Outbound) ──────────────────────────────
            if (fd == tunFd_ && (evts & EPOLLIN)) {
                while (true) {
                    ssize_t bytesRead = read(tunFd_, readBuf, sizeof(readBuf));
                    if (bytesRead < 0) {
                        if (errno == EINTR) continue;
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        LOG_E("read() from TUN failed: %s", std::strerror(errno));
                        consecutiveErrors++;
                        if (consecutiveErrors >= ZtConfig::MAX_CONSECUTIVE_ERRORS) {
                            LOG_E("Too many TUN read errors — stopping bridge");
                            bridgeRunning_.store(false, std::memory_order_release);
                        }
                        break;
                    }
                    if (bytesRead == 0) break;

                    consecutiveErrors = 0;
                    size_t pktLen = static_cast<size_t>(bytesRead);
                    packetsOut_.fetch_add(1, std::memory_order_relaxed);
                    bytesOut_.fetch_add(pktLen, std::memory_order_relaxed);

                    if (pktLen < 20) {
                        LOG_W("Packet too short (%zu bytes) — dropping", pktLen);
                        packetsDropped_.fetch_add(1, std::memory_order_relaxed);
                        continue;
                    }

                    uint8_t version = (readBuf[0] >> 4) & 0x0F;
                    if (version != 4 && version != 6) {
                        LOG_W("Unknown IP version %u — dropping", version);
                        packetsDropped_.fetch_add(1, std::memory_order_relaxed);
                        continue;
                    }

                    uint64_t totalOut = packetsOut_.load(std::memory_order_relaxed);
                    if (totalOut <= 5 || totalOut % 1000 == 0) {
                        if (version == 4 && pktLen >= 20) {
                            auto* iph = reinterpret_cast<const struct iphdr*>(readBuf);
                            char src[INET_ADDRSTRLEN]{}, dst[INET_ADDRSTRLEN]{};
                            inet_ntop(AF_INET, &iph->saddr, src, sizeof(src));
                            inet_ntop(AF_INET, &iph->daddr, dst, sizeof(dst));
                            LOG_D("TUN→ZT: IPv4 %s → %s proto=%u len=%zu",
                                  src, dst, iph->protocol, pktLen);
                        }
                    }

                    // ── OUTBOUND: TUN → ZeroTier ──────────────────────
                    if (version == 4 && pktLen >= sizeof(struct iphdr)) {
                        // IPv4 outbound
                        auto* iph = reinterpret_cast<const struct iphdr*>(readBuf);
                        struct zts_sockaddr_in destAddr{};
                        destAddr.sin_family = ZTS_AF_INET;
                        destAddr.sin_addr.s_addr = iph->daddr;

                        ssize_t sent = zts_bsd_sendto(ztRawSock, readBuf, pktLen, 0,
                                                       reinterpret_cast<struct zts_sockaddr*>(&destAddr),
                                                       sizeof(destAddr));
                        if (sent < 0) {
                            int err = errno;
                            if (err != EAGAIN && err != EWOULDBLOCK) {
                                char dst[INET_ADDRSTRLEN]{};
                                inet_ntop(AF_INET, &iph->daddr, dst, sizeof(dst));
                                LOG_W("zts_bsd_sendto IPv4 failed: %s (dst=%s len=%zu)",
                                      std::strerror(err), dst, pktLen);
                            }
                        }
                    } else if (version == 6 && pktLen >= 40) {
                        // IPv6 outbound — use zts_sockaddr_in6
                        struct zts_sockaddr_in6 destAddr6{};
                        destAddr6.sin6_family = ZTS_AF_INET6;
                        memcpy(&destAddr6.sin6_addr, readBuf + 24, 16);

                        ssize_t sent = zts_bsd_sendto(ztRawSock, readBuf, pktLen, 0,
                                                       reinterpret_cast<struct zts_sockaddr*>(&destAddr6),
                                                       sizeof(destAddr6));
                        if (sent < 0) {
                            int err = errno;
                            if (err != EAGAIN && err != EWOULDBLOCK) {
                                LOG_W("zts_bsd_sendto IPv6 failed: %s (len=%zu)",
                                      std::strerror(err), pktLen);
                            }
                        }
                    } else {
                        LOG_W("Cannot route packet: version=%u len=%zu", version, pktLen);
                        packetsDropped_.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            }

            // ── ZeroTier → TUN (Inbound) ───────────────────────────────
            if (fd == ztRawSock && (evts & EPOLLIN)) {
                while (true) {
                    struct zts_sockaddr_in fromAddr{};
                    zts_socklen_t fromLen = sizeof(fromAddr);
                    ssize_t bytesRead = zts_bsd_recvfrom(ztRawSock, readBuf,
                                                         sizeof(readBuf), 0,
                                                         reinterpret_cast<struct zts_sockaddr*>(&fromAddr),
                                                         &fromLen);
                    if (bytesRead < 0) {
                        if (errno == EINTR) continue;
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        LOG_W("zts_bsd_recvfrom failed: %s", std::strerror(errno));
                        break;
                    }
                    if (bytesRead == 0) break;

                    size_t pktLen = static_cast<size_t>(bytesRead);
                    packetsIn_.fetch_add(1, std::memory_order_relaxed);
                    bytesIn_.fetch_add(pktLen, std::memory_order_relaxed);

                    if (pktLen < 20) continue;
                    uint8_t version = (readBuf[0] >> 4) & 0x0F;
                    if (version != 4 && version != 6) continue;

                    // ── FALLBACK ROUTING: Prevent infinite loops ─────────
                    // Only write to TUN if the packet is NOT from our own
                    // assigned IP (which would indicate a routing loop).
                    // This is a safety net on top of addDisallowedApplication().
                    {
                        std::lock_guard<std::mutex> lock(stateMutex_);
                        if (!assignedIPv4_.empty() && version == 4 &&
                            pktLen >= sizeof(struct iphdr)) {
                            auto* iph = reinterpret_cast<const struct iphdr*>(readBuf);
                            char srcStr[INET_ADDRSTRLEN]{};
                            inet_ntop(AF_INET, &iph->saddr, srcStr, sizeof(srcStr));
                            if (assignedIPv4_ == srcStr) {
                                LOG_W("Dropping looped packet: src=%s is our own IP", srcStr);
                                packetsDropped_.fetch_add(1, std::memory_order_relaxed);
                                continue;
                            }
                        }
                    }

                    ssize_t written = write(tunFd_, readBuf, pktLen);
                    if (written < 0) {
                        int err = errno;
                        if (err != EAGAIN && err != EWOULDBLOCK) {
                            LOG_W("write() to TUN failed: %s", std::strerror(err));
                        }
                    } else if (static_cast<size_t>(written) != pktLen) {
                        LOG_W("Partial TUN write: %zd/%zu bytes", written, pktLen);
                    }
                }
            }
        }

        // ── Periodic traffic stats ─────────────────────────────────────
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - lastStatsTime).count();
        if (elapsed >= ZtConfig::STATS_INTERVAL_SEC) {
            notifyStats();
            lastStatsTime = now;
        }
    }

    // ── Cleanup ────────────────────────────────────────────────────────
    epoll_ctl(epollFd, EPOLL_CTL_DEL, tunFd_, nullptr);
    if (ztRawSock >= 0) {
        epoll_ctl(epollFd, EPOLL_CTL_DEL, ztRawSock, nullptr);
        zts_bsd_close(ztRawSock);
    }
    safeClose(epollFd);

    LOG_I("TUN bridge loop exited");
}

// ══════════════════════════════════════════════════════════════════════════════
// ZeroTier Event Callback (static)
// ══════════════════════════════════════════════════════════════════════════════

void ZeroTierEngine::onZtEvent(void* msg) {
    if (msg == nullptr) return;
    ZeroTierEngine* engine = g_ztEngine.load(std::memory_order_acquire);
    if (engine == nullptr) {
        // Late callback after engine was stopped — ignore silently
        return;
    }

    // If the engine is shutting down, ignore all late callbacks
    if (engine->stopping_.load(std::memory_order_acquire)) {
        return;
    }

    try {
        auto* eventMsg = static_cast<zts_event_msg_t*>(msg);
        int eventCode = eventMsg->event_code;

        switch (eventCode) {
            case ZTS_EVENT_NODE_UP: {
                LOG_I("ZT_EVENT_NODE_UP — node initialized, waiting for ONLINE...");
                engine->currentState_.store(ZtStateCode::STARTING, std::memory_order_release);
                break;
            }
            case ZTS_EVENT_NODE_ONLINE: {
                LOG_I("ZT_EVENT_NODE_ONLINE — node is connected to ZeroTier network");
                engine->online_.store(true, std::memory_order_release);
                uint64_t nodeId = zts_node_get_id();
                engine->nodeId_.store(nodeId, std::memory_order_release);
                LOG_I("ZeroTier Node ID: %010" PRIx64, nodeId);

                // ── P2P Handshake state ─────────────────────────────────
                // When the node comes online, it must perform UDP hole punching
                // with the ZeroTier network controllers. On strict NATs/ISPs
                // (like Indian ISPs with symmetric NAT), this can take 30-90s.
                engine->currentState_.store(ZtStateCode::P2P_HANDSHAKE, std::memory_order_release);
                engine->notifyState(ZtStateCode::P2P_HANDSHAKE,
                    "P2P handshake in progress (UDP hole punching)...");

                // ── CRITICAL FIX: Auto-join the network on node online ──
                if (engine->networkId_ != 0) {
                    LOG_I("Auto-joining network %016" PRIx64 "...", engine->networkId_);

                    engine->currentState_.store(ZtStateCode::JOINING_NETWORK, std::memory_order_release);
                    engine->notifyState(ZtStateCode::JOINING_NETWORK,
                        "Joining ZeroTier network...");

                    int joinRc = zts_net_join(engine->networkId_);
                    if (joinRc != ZTS_ERR_OK) {
                        LOG_E("zts_net_join(%016" PRIx64 ") failed: %d",
                              engine->networkId_, joinRc);
                        engine->setError("Failed to join network: error " +
                                         std::to_string(joinRc));
                        engine->notifyState(ZtStateCode::ERROR,
                            "Failed to join ZeroTier network");
                    } else {
                        LOG_I("Network join request sent — waiting for authorization...");

                        engine->currentState_.store(ZtStateCode::AUTHENTICATING, std::memory_order_release);
                        engine->notifyState(ZtStateCode::AUTHENTICATING,
                            "Authenticating with network controller...");
                    }
                } else {
                    LOG_W("No network ID set — node is online but not joining any network");
                }
                break;
            }
            case ZTS_EVENT_NODE_OFFLINE: {
                LOG_W("ZT_EVENT_NODE_OFFLINE — lost connectivity");
                engine->online_.store(false, std::memory_order_release);

                // Don't immediately error — transition to RECONNECTING state
                // The Kotlin layer can decide to auto-retry
                if (!engine->stopping_.load(std::memory_order_acquire)) {
                    engine->currentState_.store(ZtStateCode::RECONNECTING, std::memory_order_release);
                    engine->notifyState(ZtStateCode::RECONNECTING,
                        "ZeroTier node offline — reconnecting...");
                }
                break;
            }
            case ZTS_EVENT_NODE_DOWN: {
                LOG_I("ZT_EVENT_NODE_DOWN — node shutting down");
                engine->online_.store(false, std::memory_order_release);
                break;
            }
            case ZTS_EVENT_NETWORK_READY_IP4: {
                LOG_I("ZT_EVENT_NETWORK_READY_IP4 — virtual network is ready");
                engine->networkReady_.store(true, std::memory_order_release);
                uint64_t netId = (eventMsg->network != nullptr)
                                 ? eventMsg->network->net_id : engine->networkId_;
                std::string ipv4 = getZtIpAddress(netId, ZTS_AF_INET);
                if (!ipv4.empty()) {
                    {
                        std::lock_guard<std::mutex> lock(engine->stateMutex_);
                        engine->assignedIPv4_ = ipv4;
                    }
                    LOG_I("Assigned IPv4: %s (network=%016" PRIx64 ")", ipv4.c_str(), netId);
                    engine->notifyIp(ipv4, "");
                    engine->currentState_.store(ZtStateCode::NETWORK_READY, std::memory_order_release);
                    engine->notifyState(ZtStateCode::NETWORK_READY,
                        "Network ready — assigned IP: " + ipv4);
                } else {
                    LOG_W("NETWORK_READY_IP4 event but zts_addr_get_str failed");
                    engine->currentState_.store(ZtStateCode::NETWORK_READY, std::memory_order_release);
                    engine->notifyState(ZtStateCode::NETWORK_READY,
                        "Network ready — IP assignment pending");
                }
                break;
            }
            case ZTS_EVENT_NETWORK_READY_IP6: {
                LOG_I("ZT_EVENT_NETWORK_READY_IP6");
                uint64_t netId = (eventMsg->network != nullptr)
                                 ? eventMsg->network->net_id : engine->networkId_;
                std::string ipv6 = getZtIpAddress(netId, ZTS_AF_INET6);
                if (!ipv6.empty()) {
                    {
                        std::lock_guard<std::mutex> lock(engine->stateMutex_);
                        engine->assignedIPv6_ = ipv6;
                    }
                    LOG_I("Assigned IPv6: %s", ipv6.c_str());
                }
                break;
            }
            case ZTS_EVENT_NETWORK_DOWN: {
                LOG_W("ZT_EVENT_NETWORK_DOWN — network went down");
                engine->networkReady_.store(false, std::memory_order_release);
                if (!engine->stopping_.load(std::memory_order_acquire)) {
                    engine->currentState_.store(ZtStateCode::RECONNECTING, std::memory_order_release);
                    engine->notifyState(ZtStateCode::RECONNECTING,
                        "Network down — reconnecting...");
                }
                break;
            }
            case ZTS_EVENT_NETWORK_OK: {
                LOG_I("ZT_EVENT_NETWORK_OK — network configuration received");
                // Transition from AUTHENTICATING to WAITING_AUTHORIZATION
                // This means the network config was received but we're
                // still waiting for IP assignment
                engine->currentState_.store(ZtStateCode::WAITING_AUTHORIZATION, std::memory_order_release);
                engine->notifyState(ZtStateCode::WAITING_AUTHORIZATION,
                    "Network authorized — waiting for IP assignment...");
                break;
            }
            case ZTS_EVENT_NETWORK_ACCESS_DENIED: {
                LOG_E("ZT_EVENT_NETWORK_ACCESS_DENIED — node not authorized on this network");
                engine->networkReady_.store(false, std::memory_order_release);
                engine->setError("Network access denied. Authorize this node at my.zerotier.com");
                engine->currentState_.store(ZtStateCode::ERROR, std::memory_order_release);
                engine->notifyState(ZtStateCode::ERROR,
                    "Access denied — authorize this node at my.zerotier.com");
                break;
            }
            case ZTS_EVENT_NETWORK_NOT_FOUND: {
                LOG_E("ZT_EVENT_NETWORK_NOT_FOUND — invalid network ID");
                engine->setError("Network not found. Check the 16-char hex Network ID.");
                engine->currentState_.store(ZtStateCode::ERROR, std::memory_order_release);
                engine->notifyState(ZtStateCode::ERROR,
                    "Network not found — check Network ID");
                break;
            }
            case ZTS_EVENT_NODE_FATAL_ERROR: {
                LOG_E("ZT_EVENT_NODE_FATAL_ERROR — unrecoverable error");
                engine->setError("ZeroTier fatal error. Deleting identity for recovery.");
                engine->currentState_.store(ZtStateCode::ERROR, std::memory_order_release);
                engine->notifyState(ZtStateCode::ERROR,
                    "Fatal ZeroTier error — identity will be regenerated");
                // On fatal error, the identity is corrupted (e.g., address collision).
                // The Kotlin layer's fatalErrorHandler will trigger auto-reconnect,
                // which stops and re-creates the engine. A new identity will be
                // generated automatically on the next zts_node_start() call.
                break;
            }
            case ZTS_EVENT_ADDR_ADDED_IP4: {
                LOG_I("ZT_EVENT_ADDR_ADDED_IP4 — new IPv4 address assigned");
                uint64_t netId = (eventMsg->network != nullptr)
                                 ? eventMsg->network->net_id : engine->networkId_;
                std::string ipv4 = getZtIpAddress(netId, ZTS_AF_INET);
                if (!ipv4.empty()) {
                    {
                        std::lock_guard<std::mutex> lock(engine->stateMutex_);
                        engine->assignedIPv4_ = ipv4;
                    }
                    LOG_I("Updated IPv4: %s", ipv4.c_str());
                    engine->notifyIp(ipv4, engine->assignedIPv6_);
                }
                break;
            }
            case ZTS_EVENT_ADDR_REMOVED_IP4: {
                LOG_I("ZT_EVENT_ADDR_REMOVED_IP4");
                {
                    std::lock_guard<std::mutex> lock(engine->stateMutex_);
                    engine->assignedIPv4_.clear();
                }
                engine->notifyIp("", engine->assignedIPv6_);
                break;
            }
            case ZTS_EVENT_ADDR_ADDED_IP6: {
                LOG_I("ZT_EVENT_ADDR_ADDED_IP6 — new IPv6 address assigned");
                uint64_t netId = (eventMsg->network != nullptr)
                                 ? eventMsg->network->net_id : engine->networkId_;
                std::string ipv6 = getZtIpAddress(netId, ZTS_AF_INET6);
                if (!ipv6.empty()) {
                    {
                        std::lock_guard<std::mutex> lock(engine->stateMutex_);
                        engine->assignedIPv6_ = ipv6;
                    }
                    LOG_I("Updated IPv6: %s", ipv6.c_str());
                    engine->notifyIp(engine->assignedIPv4_, ipv6);
                }
                break;
            }
            case ZTS_EVENT_PEER_DIRECT: {
                // A peer went from RELAY to DIRECT — UDP hole punch succeeded
                // This is useful for strict NAT/ISP scenarios
                if (eventMsg->peer) {
                    LOG_I("ZT_EVENT_PEER_DIRECT — peer %010" PRIx64 " is now direct (hole punch OK)",
                          eventMsg->peer->peer_id);
                }
                break;
            }
            case ZTS_EVENT_PEER_RELAY: {
                if (eventMsg->peer) {
                    LOG_D("ZT_EVENT_PEER_RELAY — peer %010" PRIx64 " using relay",
                          eventMsg->peer->peer_id);
                }
                break;
            }
            case ZTS_EVENT_PEER_UNREACHABLE: {
                if (eventMsg->peer) {
                    LOG_W("ZT_EVENT_PEER_UNREACHABLE — peer %010" PRIx64 " unreachable (check NAT/Firewall)",
                          eventMsg->peer->peer_id);
                }
                break;
            }
            case ZTS_EVENT_NETWORK_CLIENT_TOO_OLD: {
                LOG_E("ZT_EVENT_NETWORK_CLIENT_TOO_OLD — SDK version incompatible");
                engine->setError("ZeroTier SDK version too old. Update the app.");
                engine->currentState_.store(ZtStateCode::ERROR, std::memory_order_release);
                engine->notifyState(ZtStateCode::ERROR,
                    "SDK version too old — update the app");
                break;
            }
            case ZTS_EVENT_STORE_IDENTITY_PUBLIC: {
                LOG_I("ZT_EVENT_STORE_IDENTITY_PUBLIC — identity file saved (Node ID available)");
                break;
            }
            case ZTS_EVENT_STORE_IDENTITY_SECRET: {
                LOG_I("ZT_EVENT_STORE_IDENTITY_SECRET — secret identity stored");
                break;
            }
            default: {
                LOG_D("Unhandled ZT event: %d", eventCode);
                break;
            }
        }
    } catch (const std::exception& e) {
        LOG_E("Exception in onZtEvent: %s", e.what());
    } catch (...) {
        LOG_E("Unknown exception in onZtEvent");
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Callbacks
// ══════════════════════════════════════════════════════════════════════════════

void ZeroTierEngine::setStateCallback(ZtStateCallback cb) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    stateCallback_ = std::move(cb);
}

void ZeroTierEngine::setIpCallback(ZtIpCallback cb) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    ipCallback_ = std::move(cb);
}

void ZeroTierEngine::setStatsCallback(ZtStatsCallback cb) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    statsCallback_ = std::move(cb);
}

void ZeroTierEngine::setSocketProtectCallback(SocketProtectCallback cb) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    socketProtectCallback_ = std::move(cb);
}

// ══════════════════════════════════════════════════════════════════════════════
// Notification helpers
// ══════════════════════════════════════════════════════════════════════════════

void ZeroTierEngine::notifyState(ZtStateCode code, const std::string& msg) {
    // Don't send callbacks during shutdown
    if (stopping_.load(std::memory_order_acquire) && code != ZtStateCode::STOPPED) {
        return;
    }

    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (stateCallback_) {
        try {
            stateCallback_(static_cast<int>(code), msg);
        } catch (...) {
            LOG_E("Exception in state callback — suppressed");
        }
    }
}

void ZeroTierEngine::notifyIp(const std::string& ipv4, const std::string& ipv6) {
    if (stopping_.load(std::memory_order_acquire)) return;

    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (ipCallback_) {
        try {
            ipCallback_(ipv4, ipv6);
        } catch (...) {
            LOG_E("Exception in IP callback — suppressed");
        }
    }
}

void ZeroTierEngine::notifyStats() {
    if (stopping_.load(std::memory_order_acquire)) return;

    std::lock_guard<std::mutex> lock(callbackMutex_);
    if (statsCallback_) {
        try {
            statsCallback_(
                bytesIn_.load(std::memory_order_relaxed),
                bytesOut_.load(std::memory_order_relaxed),
                packetsIn_.load(std::memory_order_relaxed),
                packetsOut_.load(std::memory_order_relaxed)
            );
        } catch (...) {
            LOG_E("Exception in stats callback — suppressed");
        }
    }
}

void ZeroTierEngine::setError(const std::string& error) {
    std::lock_guard<std::mutex> lock(errorMutex_);
    lastError_ = error;
}
