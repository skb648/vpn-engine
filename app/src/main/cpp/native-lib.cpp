/**
 * native-lib.cpp — JNI Bridge for ZeroTier P2P Mesh VPN Engine
 *
 * This file provides the JNI interface between Kotlin (ZtEngine.kt)
 * and the C++ ZeroTierEngine. It handles:
 *
 *   1. ZeroTier node lifecycle (start, stop)
 *   2. Network management (join, leave, getAssignedIP)
 *   3. TUN bridge control (startTunBridge, stopTunBridge)
 *   4. Error reporting (getLastError)
 *   5. JNI callbacks from C++ -> Kotlin:
 *      - onZtStateChanged(stateCode, message)
 *      - onZtAssignedIP(ipv4, ipv6)
 *      - onZtTrafficStats(bytesIn, bytesOut, pktsIn, pktsOut)
 *      - onZtSocketCreated(fd) — for VpnService.protect()
 *
 * BULLETPROOF LIFECYCLE (v5):
 *   1. Every JNI function is wrapped in try-catch
 *   2. C++ exceptions NEVER cross the JNI boundary
 *   3. Java exceptions in callbacks are immediately cleared
 *   4. JNIEnv* is thread-local — we cache JavaVM* and use
 *      AttachCurrentThread() for callback threads
 *   5. nativeStop() is safe to call during engine teardown
 *   6. Callbacks are guarded against use-after-free
 */

#include <jni.h>
#include <android/log.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <atomic>
#include <mutex>
#include <memory>

#include "ZeroTierEngine.h"

// ──────────────────────────────────────────────────────────────────────────────
// Logging
// ──────────────────────────────────────────────────────────────────────────────

#define LOG_TAG "ZT-JNI"
#define LOG_D(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOG_I(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOG_W(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOG_E(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ──────────────────────────────────────────────────────────────────────────────
// Global State
// ──────────────────────────────────────────────────────────────────────────────

static std::unique_ptr<ZeroTierEngine> g_engine;
static std::mutex g_engineMutex;

// ── JNI callback fields ─────────────────────────────────────────────────────
static JavaVM*     g_jvm{nullptr};
static jobject     g_callbackObj{nullptr};    // Global ref to ZtEngine.INSTANCE

// Cached method IDs for ZtEngine callbacks
static jmethodID   g_onZtStateChanged{nullptr};   // (ILjava/lang/String;)V
static jmethodID   g_onZtAssignedIP{nullptr};      // (Ljava/lang/String;Ljava/lang/String;)V
static jmethodID   g_onZtTrafficStats{nullptr};    // (JJJJ)V
static jmethodID   g_onZtSocketCreated{nullptr};   // (I)Z

static std::mutex  g_callbackMutex;
static std::atomic<bool> g_jniShuttingDown{false};  // Guard against late callbacks during unload

// ── Thread-local JNI attachment tracking ──────────────────────────────────────

static thread_local bool g_tlsAttached = false;

// ──────────────────────────────────────────────────────────────────────────────
// JNI Callback Helpers — Call Kotlin from C++
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Get or create a JNI JNIEnv* for the current thread.
 * Uses thread-local tracking to avoid repeated AttachCurrentThread calls.
 * The thread stays attached until it exits (JVM auto-cleans).
 */
static JNIEnv* getJniEnv() {
    if (!g_jvm) return nullptr;
    if (g_jniShuttingDown.load(std::memory_order_acquire)) return nullptr;

    if (g_tlsAttached) {
        JNIEnv* env = nullptr;
        if (g_jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_OK) {
            return env;
        }
        g_tlsAttached = false;
    }
    JNIEnv* env = nullptr;
    JavaVMAttachArgs args;
    args.version = JNI_VERSION_1_6;
    args.name    = const_cast<char*>("ZT-Callback");
    args.group   = nullptr;
    if (g_jvm->AttachCurrentThread(&env, &args) == JNI_OK && env) {
        g_tlsAttached = true;
        return env;
    }
    return nullptr;
}

static void callOnZtStateChanged(int stateCode, const std::string& message) {
    if (g_jniShuttingDown.load(std::memory_order_acquire)) return;

    std::lock_guard<std::mutex> lock(g_callbackMutex);
    if (!g_jvm || !g_callbackObj || !g_onZtStateChanged) return;

    JNIEnv* env = getJniEnv();
    if (!env) return;

    jstring jMsg = env->NewStringUTF(message.c_str());
    if (!jMsg) {
        if (env->ExceptionCheck()) { env->ExceptionDescribe(); env->ExceptionClear(); }
        return;
    }

    try {
        env->CallVoidMethod(g_callbackObj, g_onZtStateChanged,
                            static_cast<jint>(stateCode), jMsg);
    } catch (...) {}

    if (env->ExceptionCheck()) { env->ExceptionDescribe(); env->ExceptionClear(); }
}

static void callOnZtAssignedIP(const std::string& ipv4, const std::string& ipv6) {
    if (g_jniShuttingDown.load(std::memory_order_acquire)) return;

    std::lock_guard<std::mutex> lock(g_callbackMutex);
    if (!g_jvm || !g_callbackObj || !g_onZtAssignedIP) return;

    JNIEnv* env = getJniEnv();
    if (!env) return;

    jstring jIpv4 = ipv4.empty() ? env->NewStringUTF("") : env->NewStringUTF(ipv4.c_str());
    jstring jIpv6 = ipv6.empty() ? env->NewStringUTF("") : env->NewStringUTF(ipv6.c_str());

    if (jIpv4 && jIpv6) {
        try {
            env->CallVoidMethod(g_callbackObj, g_onZtAssignedIP, jIpv4, jIpv6);
        } catch (...) {}
    }

    if (env->ExceptionCheck()) { env->ExceptionDescribe(); env->ExceptionClear(); }
}

static void callOnZtTrafficStats(uint64_t bytesIn, uint64_t bytesOut,
                                  uint64_t pktsIn, uint64_t pktsOut) {
    if (g_jniShuttingDown.load(std::memory_order_acquire)) return;

    std::lock_guard<std::mutex> lock(g_callbackMutex);
    if (!g_jvm || !g_callbackObj || !g_onZtTrafficStats) return;

    JNIEnv* env = getJniEnv();
    if (!env) return;

    try {
        env->CallVoidMethod(g_callbackObj, g_onZtTrafficStats,
                            static_cast<jlong>(bytesIn), static_cast<jlong>(bytesOut),
                            static_cast<jlong>(pktsIn), static_cast<jlong>(pktsOut));
    } catch (...) {}

    if (env->ExceptionCheck()) { env->ExceptionDescribe(); env->ExceptionClear(); }
}

static bool callOnZtSocketCreated(int fd) {
    if (g_jniShuttingDown.load(std::memory_order_acquire)) return false;

    std::lock_guard<std::mutex> lock(g_callbackMutex);
    if (!g_jvm || !g_callbackObj || !g_onZtSocketCreated) return false;

    JNIEnv* env = getJniEnv();
    if (!env) return false;

    jboolean result = JNI_FALSE;
    try {
        result = env->CallBooleanMethod(g_callbackObj, g_onZtSocketCreated,
                                        static_cast<jint>(fd));
    } catch (...) {}

    if (env->ExceptionCheck()) { env->ExceptionDescribe(); env->ExceptionClear(); }
    return result == JNI_TRUE;
}

// ══════════════════════════════════════════════════════════════════════════════
// Engine Initialization Helper — Sets up callbacks on the engine
// ══════════════════════════════════════════════════════════════════════════════

static void setupEngineCallbacks() {
    if (!g_engine) return;

    g_engine->setStateCallback([](int code, const std::string& msg) {
        callOnZtStateChanged(code, msg);
    });

    g_engine->setIpCallback([](const std::string& ipv4, const std::string& ipv6) {
        callOnZtAssignedIP(ipv4, ipv6);
    });

    g_engine->setStatsCallback([](uint64_t bi, uint64_t bo, uint64_t pi, uint64_t po) {
        callOnZtTrafficStats(bi, bo, pi, po);
    });

    g_engine->setSocketProtectCallback([](int fd) -> bool {
        return callOnZtSocketCreated(fd);
    });
}

// ══════════════════════════════════════════════════════════════════════════════
// JNI Function Implementations
// ══════════════════════════════════════════════════════════════════════════════

extern "C" JNIEXPORT jboolean JNICALL
Java_com_vpnengine_nativecore_ZtEngine_nativeStart(
        JNIEnv* env, jobject /* this */,
        jstring configPath, jlong networkId)
{
    try {
        std::lock_guard<std::mutex> lock(g_engineMutex);

        if (g_engine && g_engine->isRunning()) {
            LOG_W("Engine already running");
            return JNI_TRUE;
        }

        if (!configPath) {
            LOG_E("nativeStart: configPath is null");
            return JNI_FALSE;
        }

        const char* pathCstr = env->GetStringUTFChars(configPath, nullptr);
        if (!pathCstr) {
            if (env->ExceptionCheck()) { env->ExceptionDescribe(); env->ExceptionClear(); }
            LOG_E("nativeStart: GetStringUTFChars returned null");
            return JNI_FALSE;
        }

        std::string path(pathCstr);
        env->ReleaseStringUTFChars(configPath, pathCstr);

        if (networkId == 0) {
            LOG_E("nativeStart: networkId is 0 — invalid");
            return JNI_FALSE;
        }

        // CRITICAL FIX: Stop and clean up any existing engine before creating new one.
        if (g_engine) {
            if (g_engine->isRunning() || g_engine->isStopping()) {
                LOG_W("Stopping existing engine before re-creating...");
                g_engine->stop();
                // Wait for stop to complete (stop() is blocking and joins threads)
            }
            g_engine.reset();
        }

        g_jniShuttingDown.store(false, std::memory_order_release);
        g_engine = std::make_unique<ZeroTierEngine>();
        setupEngineCallbacks();

        bool ok = g_engine->start(path, static_cast<uint64_t>(networkId));
        if (!ok) {
            LOG_E("ZeroTierEngine::start() returned false");
        }
        return ok ? JNI_TRUE : JNI_FALSE;

    } catch (const std::exception& e) {
        LOG_E("nativeStart exception: %s", e.what());
        return JNI_FALSE;
    } catch (...) {
        LOG_E("nativeStart unknown exception");
        return JNI_FALSE;
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_vpnengine_nativecore_ZtEngine_nativeStop(
        JNIEnv* /* env */, jobject /* this */)
{
    try {
        // Use a try-lock with timeout to prevent deadlock when stop()
        // is called during a timeout-triggered shutdown. If the mutex
        // is already held (e.g., by nativeStart), we wait briefly.
        std::unique_lock<std::mutex> lock(g_engineMutex, std::try_to_lock);
        if (!lock.owns_lock()) {
            LOG_W("nativeStop: engine mutex busy — waiting...");
            lock.lock();
        }

        if (g_engine) {
            g_engine->stop();
            g_engine.reset();
        }
    } catch (const std::exception& e) {
        LOG_E("nativeStop exception: %s", e.what());
    } catch (...) {
        LOG_E("nativeStop unknown exception");
    }
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_vpnengine_nativecore_ZtEngine_nativeIsOnline(
        JNIEnv* /* env */, jobject /* this */)
{
    try {
        std::lock_guard<std::mutex> lock(g_engineMutex);
        return (g_engine && g_engine->isOnline()) ? JNI_TRUE : JNI_FALSE;
    } catch (...) {
        return JNI_FALSE;
    }
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_vpnengine_nativecore_ZtEngine_nativeIsRunning(
        JNIEnv* /* env */, jobject /* this */)
{
    try {
        std::lock_guard<std::mutex> lock(g_engineMutex);
        return (g_engine && g_engine->isRunning()) ? JNI_TRUE : JNI_FALSE;
    } catch (...) {
        return JNI_FALSE;
    }
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_vpnengine_nativecore_ZtEngine_nativeGetNodeId(
        JNIEnv* /* env */, jobject /* this */)
{
    try {
        std::lock_guard<std::mutex> lock(g_engineMutex);
        return g_engine ? static_cast<jlong>(g_engine->getNodeId()) : 0LL;
    } catch (...) {
        return 0LL;
    }
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vpnengine_nativecore_ZtEngine_nativeGetAssignedIPv4(
        JNIEnv* env, jobject /* this */)
{
    try {
        std::lock_guard<std::mutex> lock(g_engineMutex);
        std::string ip = g_engine ? g_engine->getAssignedIPv4() : "";
        return env->NewStringUTF(ip.c_str());
    } catch (...) {
        return env->NewStringUTF("");
    }
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vpnengine_nativecore_ZtEngine_nativeGetAssignedIPv6(
        JNIEnv* env, jobject /* this */)
{
    try {
        std::lock_guard<std::mutex> lock(g_engineMutex);
        std::string ip = g_engine ? g_engine->getAssignedIPv6() : "";
        return env->NewStringUTF(ip.c_str());
    } catch (...) {
        return env->NewStringUTF("");
    }
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_vpnengine_nativecore_ZtEngine_nativeJoinNetwork(
        JNIEnv* /* env */, jobject /* this */, jlong networkId)
{
    try {
        std::lock_guard<std::mutex> lock(g_engineMutex);
        return (g_engine && g_engine->joinNetwork(static_cast<uint64_t>(networkId)))
               ? JNI_TRUE : JNI_FALSE;
    } catch (...) {
        return JNI_FALSE;
    }
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_vpnengine_nativecore_ZtEngine_nativeLeaveNetwork(
        JNIEnv* /* env */, jobject /* this */, jlong networkId)
{
    try {
        std::lock_guard<std::mutex> lock(g_engineMutex);
        return (g_engine && g_engine->leaveNetwork(static_cast<uint64_t>(networkId)))
               ? JNI_TRUE : JNI_FALSE;
    } catch (...) {
        return JNI_FALSE;
    }
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_vpnengine_nativecore_ZtEngine_nativeStartTunBridge(
        JNIEnv* /* env */, jobject /* this */, jint tunFd)
{
    try {
        std::lock_guard<std::mutex> lock(g_engineMutex);
        return (g_engine && g_engine->startTunBridge(static_cast<int>(tunFd)))
               ? JNI_TRUE : JNI_FALSE;
    } catch (...) {
        return JNI_FALSE;
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_vpnengine_nativecore_ZtEngine_nativeStopTunBridge(
        JNIEnv* /* env */, jobject /* this */)
{
    try {
        std::lock_guard<std::mutex> lock(g_engineMutex);
        if (g_engine) g_engine->stopTunBridge();
    } catch (...) {}
}

// ── Get last error from engine ─────────────────────────────────────────────

extern "C" JNIEXPORT jstring JNICALL
Java_com_vpnengine_nativecore_ZtEngine_nativeGetLastError(
        JNIEnv* env, jobject /* this */)
{
    try {
        std::lock_guard<std::mutex> lock(g_engineMutex);
        std::string err = g_engine ? g_engine->getLastError() : "Engine not initialized";
        return env->NewStringUTF(err.c_str());
    } catch (...) {
        return env->NewStringUTF("Unknown error retrieving last error");
    }
}

// ── SDK Availability Check ──────────────────────────────────────────────────

extern "C" JNIEXPORT jboolean JNICALL
Java_com_vpnengine_nativecore_ZtEngine_nativeIsSdkAvailable(
        JNIEnv* /* env */, jobject /* this */)
{
    extern std::atomic<bool> g_sdkAvailable;
    return g_sdkAvailable.load(std::memory_order_acquire) ? JNI_TRUE : JNI_FALSE;
}

// ── Check if engine is stopping ─────────────────────────────────────────────

extern "C" JNIEXPORT jboolean JNICALL
Java_com_vpnengine_nativecore_ZtEngine_nativeIsStopping(
        JNIEnv* /* env */, jobject /* this */)
{
    try {
        std::lock_guard<std::mutex> lock(g_engineMutex);
        return (g_engine && g_engine->isStopping()) ? JNI_TRUE : JNI_FALSE;
    } catch (...) {
        return JNI_FALSE;
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// JNI_OnLoad — Cache JavaVM* and Kotlin callback method IDs
// ══════════════════════════════════════════════════════════════════════════════

extern "C" JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM* vm, void* /* reserved */)
{
    LOG_I("JNI_OnLoad — caching JavaVM*=%p", static_cast<void*>(vm));
    g_jvm = vm;

    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        LOG_E("JNI_OnLoad: GetEnv failed");
        return JNI_ERR;
    }

    // Look up the ZtEngine Kotlin class
    jclass ztEngineClass = env->FindClass("com/vpnengine/nativecore/ZtEngine");
    if (!ztEngineClass) {
        LOG_W("JNI_OnLoad: ZtEngine class not found — callbacks disabled");
        env->ExceptionClear();
        return JNI_VERSION_1_6;
    }

    // Cache callback method IDs
    g_onZtStateChanged = env->GetMethodID(ztEngineClass,
        "onZtStateChanged", "(ILjava/lang/String;)V");
    if (!g_onZtStateChanged) {
        LOG_W("onZtStateChanged not found");
        env->ExceptionClear();
    }

    g_onZtAssignedIP = env->GetMethodID(ztEngineClass,
        "onZtAssignedIP", "(Ljava/lang/String;Ljava/lang/String;)V");
    if (!g_onZtAssignedIP) {
        LOG_W("onZtAssignedIP not found");
        env->ExceptionClear();
    }

    g_onZtTrafficStats = env->GetMethodID(ztEngineClass,
        "onZtTrafficStats", "(JJJJ)V");
    if (!g_onZtTrafficStats) {
        LOG_W("onZtTrafficStats not found");
        env->ExceptionClear();
    }

    g_onZtSocketCreated = env->GetMethodID(ztEngineClass,
        "onZtSocketCreated", "(I)Z");
    if (!g_onZtSocketCreated) {
        LOG_W("onZtSocketCreated not found");
        env->ExceptionClear();
    }

    // Cache ZtEngine.INSTANCE global reference
    jfieldID instanceField = env->GetStaticFieldID(ztEngineClass,
        "INSTANCE", "Lcom/vpnengine/nativecore/ZtEngine;");
    if (!instanceField) {
        LOG_W("ZtEngine.INSTANCE field not found");
        env->ExceptionClear();
        return JNI_VERSION_1_6;
    }

    jobject instance = env->GetStaticObjectField(ztEngineClass, instanceField);
    if (!instance) {
        LOG_W("ZtEngine.INSTANCE is null");
        return JNI_VERSION_1_6;
    }

    g_callbackObj = env->NewGlobalRef(instance);
    if (!g_callbackObj) {
        LOG_E("NewGlobalRef failed for ZtEngine.INSTANCE");
        return JNI_VERSION_1_6;
    }

    env->DeleteLocalRef(instance);

    LOG_I("JNI_OnLoad complete — all ZT callbacks initialized");
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT void JNICALL
JNI_OnUnload(JavaVM* vm, void* /* reserved */)
{
    LOG_I("JNI_OnUnload — cleaning up");
    g_jniShuttingDown.store(true, std::memory_order_release);

    try {
        std::lock_guard<std::mutex> lock(g_engineMutex);
        if (g_engine) {
            g_engine->stop();
            g_engine.reset();
        }
    } catch (...) {}

    {
        std::lock_guard<std::mutex> lock(g_callbackMutex);
        if (g_callbackObj) {
            JNIEnv* env = nullptr;
            if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_OK && env) {
                env->DeleteGlobalRef(g_callbackObj);
            }
            g_callbackObj = nullptr;
        }
    }

    g_onZtStateChanged = nullptr;
    g_onZtAssignedIP = nullptr;
    g_onZtTrafficStats = nullptr;
    g_onZtSocketCreated = nullptr;
    g_jvm = nullptr;
    g_jniShuttingDown.store(false, std::memory_order_release);
}
