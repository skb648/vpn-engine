package com.vpnengine.nativecore

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.POST
import retrofit2.http.Path
import java.util.concurrent.TimeUnit

/**
 * ZeroTier Central API Client — Production-grade Retrofit-based API integration.
 *
 * This provides REAL working integration with my.zerotier.com API:
 *   - Get network info and members
 *   - Check if a node is authorized
 *   - Auto-authorize nodes (with API token)
 *   - Get network configuration
 *
 * The Central API is the ONLY way to programmatically manage ZeroTier networks.
 * The native SDK (libzt) alone CANNOT authorize nodes — authorization must
 * happen via the Central web dashboard OR this API.
 *
 * API Base: https://my.zerotier.com/api/
 * Auth: Bearer token from https://my.zerotier.com/account#tokens
 *
 * BULLETPROOF DESIGN:
 *   - Every call wrapped in try-catch
 *   - Exponential backoff retry on network failures
 *   - Proper error messages for all failure modes
 *   - No crashes, no ANRs — all coroutine-based
 */
object ZtCentralApi {

    private const val TAG = "ZtCentralApi"
    private const val BASE_URL = "https://my.zerotier.com/api/"
    private const val CONNECT_TIMEOUT_SEC = 15L
    private const val READ_TIMEOUT_SEC = 20L

    // Retry configuration
    private const val MAX_RETRIES = 3
    private const val RETRY_BASE_DELAY_MS = 1000L

    // CRITICAL FIX: Singleton OkHttpClient to prevent thread/socket exhaustion.
    // Previously, a new OkHttpClient (with its own 5-thread pool and connection pool)
    // was created on every API call, exhausting threads and sockets over time.
    private val sharedClient: OkHttpClient by lazy {
        val logging = HttpLoggingInterceptor().apply {
            level = if (BuildConfig.DEBUG) {
                HttpLoggingInterceptor.Level.BASIC
            } else {
                HttpLoggingInterceptor.Level.NONE
            }
        }
        OkHttpClient.Builder()
            .connectTimeout(CONNECT_TIMEOUT_SEC, TimeUnit.SECONDS)
            .readTimeout(READ_TIMEOUT_SEC, TimeUnit.SECONDS)
            .writeTimeout(READ_TIMEOUT_SEC, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true)
            .addInterceptor(logging)
            .build()
    }

    // Cache the Retrofit service instance per base URL (only one in practice)
    @Volatile
    private var cachedService: ZtCentralService? = null

    fun createService(apiToken: String): ZtCentralService {
        // Return cached service if available — the auth token is passed per-request
        // via the @Header("Authorization") parameter, so the service itself is token-agnostic
        cachedService?.let { return it }

        val service = Retrofit.Builder()
            .baseUrl(BASE_URL)
            .client(sharedClient)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(ZtCentralService::class.java)

        cachedService = service
        return service
    }

    /**
     * Check if a node is authorized on a network.
     * This is the KEY function that bridges the gap between the app
     * and the ZeroTier Central dashboard.
     *
     * @param apiToken ZeroTier Central API token
     * @param networkId 16-character hex network ID
     * @param nodeId 10-character hex node ID
     * @return Authorization status
     */
    suspend fun isNodeAuthorized(
        apiToken: String,
        networkId: String,
        nodeId: String
    ): Result<Boolean> = withRetry {
        val service = createService(apiToken)
        val member = service.getNetworkMember(
            auth = "Bearer $apiToken",
            networkId = networkId,
            nodeId = nodeId
        )
        Result.success(member.config?.authorized == true)
    }

    /**
     * Authorize a node on the network.
     * This enables the node to receive an IP and join the virtual network.
     *
     * @param apiToken ZeroTier Central API token
     * @param networkId 16-character hex network ID
     * @param nodeId 10-character hex node ID
     * @return Success or failure
     */
    suspend fun authorizeNode(
        apiToken: String,
        networkId: String,
        nodeId: String
    ): Result<Unit> = withRetry {
        val service = createService(apiToken)
        val body = AuthorizeMemberRequest(
            config = MemberConfig(authorized = true)
        )
        try {
            service.authorizeMember(
                auth = "Bearer $apiToken",
                networkId = networkId,
                nodeId = nodeId,
                body = body
            )
            Log.i(TAG, "Node $nodeId authorized on network $networkId")
            Result.success(Unit)
        } catch (e: retrofit2.HttpException) {
            // CRITICAL FIX: Provide user-friendly error messages instead of
            // raw HTTP exception stacktraces
            val userMessage = when (e.code()) {
                401 -> "Invalid API token. Check your ZeroTier Central API token at my.zerotier.com/account#tokens"
                403 -> "Permission denied. Your API token may not have write access to this network."
                404 -> "Network or node not found. Check your Network ID and ensure the node has tried to join."
                else -> "Authorization failed: HTTP ${e.code()} — ${e.message()}"
            }
            Log.e(TAG, "authorizeNode failed: $userMessage")
            Result.failure(Exception(userMessage, e))
        }
    }

    /**
     * Get network information including member list.
     *
     * @param apiToken ZeroTier Central API token
     * @param networkId 16-character hex network ID
     * @return Network info with members
     */
    suspend fun getNetworkInfo(
        apiToken: String,
        networkId: String
    ): Result<NetworkInfo> = withRetry {
        val service = createService(apiToken)
        val info = service.getNetwork(
            auth = "Bearer $apiToken",
            networkId = networkId
        )
        Result.success(info)
    }

    /**
     * Get all members of a network.
     *
     * @param apiToken ZeroTier Central API token
     * @param networkId 16-character hex network ID
     * @return List of network members
     */
    suspend fun getNetworkMembers(
        apiToken: String,
        networkId: String
    ): Result<List<NetworkMember>> = withRetry {
        val service = createService(apiToken)
        val members = service.getNetworkMembers(
            auth = "Bearer $apiToken",
            networkId = networkId
        )
        Result.success(members)
    }

    /**
     * Check network and authorization status comprehensively.
     * Returns a detailed status for UI display.
     */
    suspend fun checkAuthorizationStatus(
        apiToken: String,
        networkId: String,
        nodeId: String
    ): AuthorizationStatus = withContext(Dispatchers.IO) {
        try {
            // First check if the network exists
            val networkResult = getNetworkInfo(apiToken, networkId)
            if (networkResult.isFailure) {
                return@withContext AuthorizationStatus.Error(
                    "Network not found. Check your Network ID and API token."
                )
            }

            // Check if node is a member
            val memberResult = withRetry {
                val service = createService(apiToken)
                try {
                    val member = service.getNetworkMember(
                        auth = "Bearer $apiToken",
                        networkId = networkId,
                        nodeId = nodeId
                    )
                    Result.success(member)
                } catch (e: retrofit2.HttpException) {
                    if (e.code() == 404) {
                        // Node not found as member — it hasn't tried to join yet
                        Result.success(null)
                    } else {
                        throw e
                    }
                }
            }

            val member = memberResult.getOrNull()
            when {
                member == null -> {
                    // Node hasn't appeared on the network yet
                    AuthorizationStatus.Pending(
                        "Node not yet visible. Waiting for ZeroTier SDK to register..."
                    )
                }
                member.config?.authorized == true -> {
                    AuthorizationStatus.Authorized(
                        "Node is authorized on the network."
                    )
                }
                else -> {
                    AuthorizationStatus.NotAuthorized(
                        "Node is visible but NOT authorized. Authorize at my.zerotier.com or provide API token for auto-auth."
                    )
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to check authorization status", e)
            AuthorizationStatus.Error(
                "API check failed: ${e.message ?: "Unknown error"}"
            )
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // Retry helper with exponential backoff
    // ══════════════════════════════════════════════════════════════════════

    private suspend fun <T> withRetry(
        block: suspend () -> Result<T>
    ): Result<T> = withContext(Dispatchers.IO) {
        var lastException: Exception? = null
        for (attempt in 1..MAX_RETRIES) {
            try {
                return@withContext block()
            } catch (e: kotlinx.coroutines.CancellationException) {
                // CRITICAL FIX: Never catch CancellationException —
                // it must be rethrown so coroutines can be cancelled properly.
                // Previously this was caught by the general Exception handler,
                // causing service teardown to hang for 3+ seconds per API call.
                throw e
            } catch (e: Exception) {
                lastException = e
                Log.w(TAG, "API call failed (attempt $attempt/$MAX_RETRIES): ${e.message}")
                if (attempt < MAX_RETRIES) {
                    val delayMs = RETRY_BASE_DELAY_MS * (1L shl (attempt - 1))
                    delay(delayMs)
                }
            }
        }
        Result.failure(lastException ?: RuntimeException("Unknown API error"))
    }
}

// ══════════════════════════════════════════════════════════════════════════
// Data Models — ZeroTier Central API Response/Request
// ══════════════════════════════════════════════════════════════════════════

sealed class AuthorizationStatus {
    data class Authorized(val message: String) : AuthorizationStatus()
    data class NotAuthorized(val message: String) : AuthorizationStatus()
    data class Pending(val message: String) : AuthorizationStatus()
    data class Error(val message: String) : AuthorizationStatus()
}

data class NetworkInfo(
    val id: String? = null,
    val type: String? = null,
    val config: NetworkConfig? = null,
    val description: String? = null,
    val rulesSource: String? = null,
    val permissions: Map<String, Permission>? = null,
    val ownerId: String? = null,
    val onlineMemberCount: Int? = null,
    val authorizedMemberCount: Int? = null,
    val totalMemberCount: Int? = null,
    val capabilitiesByName: Map<String, Any>? = null,
    val tagsByName: Map<String, Any>? = null,
    val ui: Map<String, Any>? = null,
    val clock: Long? = null
)

data class NetworkConfig(
    val authTokens: Map<String, String>? = null,
    val creationTime: Long? = null,
    val enableBroadcast: Boolean? = null,
    val id: String? = null,
    val ipAssignmentPools: List<IpAssignmentPool>? = null,
    val mtu: Int? = null,
    val multicastLimit: Int? = null,
    val name: String? = null,
    val private: Boolean? = null,
    val ipv4AssignMode: Map<String, Boolean>? = null,
    val ipv6AssignMode: Map<String, Boolean>? = null,
    val routes: List<Route>? = null,
    val rules: List<Map<String, Any>>? = null,
    val tags: List<List<Any>>? = null,
    val v4AssignMode: Map<String, Boolean>? = null,
    val v6AssignMode: Map<String, Boolean>? = null
)

data class IpAssignmentPool(
    val ipRangeStart: String? = null,
    val ipRangeEnd: String? = null
)

data class Route(
    val target: String? = null,
    val via: String? = null
)

data class Permission(
    val a: Boolean? = null,
    val d: Boolean? = null,
    val m: Boolean? = null,
    val r: Boolean? = null,
    val w: Boolean? = null
)

data class NetworkMember(
    val id: String? = null,
    val type: String? = null,
    val clock: Long? = null,
    val networkId: String? = null,
    val nodeId: String? = null,
    val controllerId: String? = null,
    val hidden: Boolean? = null,
    val name: String? = null,
    val description: String? = null,
    val config: MemberConfig? = null,
    val lastOnline: Long? = null,
    val lastOnlineVersion: String? = null,
    val physicalAddress: String? = null,
    val physicalLocation: List<Double>? = null,
    val clientVersion: String? = null,
    val protocolVersion: Int? = null,
    val supportsRulesEngine: Boolean? = null,
    val noAutoAssignIps: Boolean? = null,
    val ssoState: Int? = null,
    val ssoExempt: Boolean? = null
)

data class MemberConfig(
    val activeBridge: Boolean? = null,
    val authorized: Boolean? = null,
    val capabilities: List<Int>? = null,
    val creationTime: Long? = null,
    val id: String? = null,
    val identity: String? = null,
    val ipAssignments: List<String>? = null,
    val lastAuthorizedTime: Long? = null,
    val lastDeauthorizedTime: Long? = null,
    val noAutoAssignIps: Boolean? = null,
    val revision: Int? = null,
    val tags: List<List<Any>>? = null,
    val vRev: Int? = null,
    val vmMajor: Int? = null,
    val vmMinor: Int? = null,
    val vmRev: Int? = null,
    val vProto: Int? = null
)

data class AuthorizeMemberRequest(
    val config: MemberConfig
)

// ══════════════════════════════════════════════════════════════════════════
// Retrofit Service Interface
// ══════════════════════════════════════════════════════════════════════════

interface ZtCentralService {

    @GET("network/{networkId}")
    suspend fun getNetwork(
        @Header("Authorization") auth: String,
        @Path("networkId") networkId: String
    ): NetworkInfo

    @GET("network/{networkId}/member")
    suspend fun getNetworkMembers(
        @Header("Authorization") auth: String,
        @Path("networkId") networkId: String
    ): List<NetworkMember>

    @GET("network/{networkId}/member/{nodeId}")
    suspend fun getNetworkMember(
        @Header("Authorization") auth: String,
        @Path("networkId") networkId: String,
        @Path("nodeId") nodeId: String
    ): NetworkMember

    @POST("network/{networkId}/member/{nodeId}")
    suspend fun authorizeMember(
        @Header("Authorization") auth: String,
        @Path("networkId") networkId: String,
        @Path("nodeId") nodeId: String,
        @Body body: AuthorizeMemberRequest
    )
}
