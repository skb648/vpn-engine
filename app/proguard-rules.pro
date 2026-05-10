# ── ZeroTier JNI Callbacks ──────────────────────────────────────────────────
# These methods are called from C++ via cached JNI method IDs.
# They MUST NOT be removed or renamed by ProGuard.
-keepclassmembers class com.vpnengine.nativecore.ZtEngine {
    void onZtStateChanged(int, java.lang.String);
    void onZtAssignedIP(java.lang.String, java.lang.String);
    void onZtTrafficStats(long, long, long, long);
    boolean onZtSocketCreated(int);
}

# ── ZeroTier SDK native methods ────────────────────────────────────────────
# These are declared as 'external' in Kotlin and called from C++.
# ProGuard must not remove or rename them.
-keepclassmembers class com.vpnengine.nativecore.ZtEngine {
    boolean nativeStart(java.lang.String, long);
    void nativeStop();
    boolean nativeIsOnline();
    boolean nativeIsRunning();
    long nativeGetNodeId();
    java.lang.String nativeGetAssignedIPv4();
    java.lang.String nativeGetAssignedIPv6();
    boolean nativeJoinNetwork(long);
    boolean nativeLeaveNetwork(long);
    boolean nativeStartTunBridge(int);
    void nativeStopTunBridge();
    java.lang.String nativeGetLastError();
    boolean nativeIsSdkAvailable();
}

# ── Keep the ZtEngine singleton INSTANCE ────────────────────────────────────
# The C++ JNI_OnLoad caches a global reference to ZtEngine.INSTANCE.
-keep class com.vpnengine.nativecore.ZtEngine {
    public static ** INSTANCE;
}

# ── VpnState sealed interface and all implementations ───────────────────────
# Used in when-expressions and state comparisons — all subclasses must be kept.
-keep class * implements com.vpnengine.nativecore.VpnState { *; }

# ── VpnStateHolder and inner classes ────────────────────────────────────────
-keep class com.vpnengine.nativecore.VpnStateHolder { *; }
-keep class com.vpnengine.nativecore.VpnStateHolder$TrafficStats { *; }
-keep class com.vpnengine.nativecore.VpnStateHolder$VpnMode { *; }

# ── VpnService subclass ─────────────────────────────────────────────────────
# Android framework requires this class to be kept for VPN permission handling.
-keep class * extends android.net.VpnService { *; }

# ── BroadcastReceiver subclass ───────────────────────────────────────────────
-keep class * extends android.content.BroadcastReceiver { *; }

# ── Socks5ProxyServer ───────────────────────────────────────────────────────
# Inner data classes used in protocol handling must be kept.
-keep class com.vpnengine.nativecore.Socks5ProxyServer { *; }
-keep class com.vpnengine.nativecore.Socks5ProxyServer$ConnectRequest { *; }

# ── ServerConfig (DataStore) ────────────────────────────────────────────────
-keep class com.vpnengine.nativecore.ServerConfig { *; }

# ── Kotlin Coroutines ───────────────────────────────────────────────────────
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-keepclassmembers class kotlinx.coroutines.** {
    <fields>;
}

# ── DataStore Preferences ───────────────────────────────────────────────────
-keep class * extends com.google.protobuf.GeneratedMessageLite { *; }

# ── Compose ─────────────────────────────────────────────────────────────────
-dontwarn androidx.compose.**
