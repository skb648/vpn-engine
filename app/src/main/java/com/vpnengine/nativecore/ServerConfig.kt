package com.vpnengine.nativecore

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

/**
 * ServerConfig — Persistent configuration using Jetpack DataStore Preferences.
 *
 * Stores:
 *   - ZeroTier Network ID (16-char hex string)
 *   - ZeroTier Central API Token (for auto-authorization)
 *
 * Uses DataStore (not SharedPreferences) because it is coroutine-based,
 * type-safe, avoids ANRs, and provides reactive Flow-based observation.
 */
class ServerConfig(private val context: Context) {

    companion object {
        private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(
            name = "vpn_settings"
        )

        // ── Preference Keys ─────────────────────────────────────────────────
        private val NETWORK_ID_KEY = stringPreferencesKey("network_id")
        private val API_TOKEN_KEY = stringPreferencesKey("api_token")

        // ── Legacy keys (kept for migration) ────────────────────────────────
        private val SERVER_HOST_KEY = stringPreferencesKey("server_host")
    }

    /**
     * Reactive Flow of the saved ZeroTier Network ID (16-char hex string).
     * Emits empty string if no value has been saved yet.
     */
    val networkId: Flow<String> = context.dataStore.data.map { preferences ->
        val directId = preferences[NETWORK_ID_KEY]
        if (!directId.isNullOrBlank()) {
            directId
        } else {
            // Migration: try to read from legacy "server_host" key
            val legacyHost = preferences[SERVER_HOST_KEY]
            if (!legacyHost.isNullOrBlank() && legacyHost != "127.0.0.1") {
                legacyHost
            } else {
                ""
            }
        }
    }

    /**
     * Reactive Flow of the saved ZeroTier Central API Token.
     * Emits empty string if no token has been saved.
     */
    val apiToken: Flow<String> = context.dataStore.data.map { preferences ->
        preferences[API_TOKEN_KEY] ?: ""
    }

    /**
     * Persist the ZeroTier Network ID to DataStore.
     *
     * @param hexId The 16-character hex Network ID string.
     */
    suspend fun saveNetworkId(hexId: String) {
        context.dataStore.edit { settings ->
            settings[NETWORK_ID_KEY] = hexId
            // Clear legacy key if present
            if (settings.contains(SERVER_HOST_KEY)) {
                settings.remove(SERVER_HOST_KEY)
            }
        }
    }

    /**
     * Persist the ZeroTier Central API Token to DataStore.
     *
     * @param token The API token from my.zerotier.com/account#tokens
     */
    suspend fun saveApiToken(token: String) {
        context.dataStore.edit { settings ->
            settings[API_TOKEN_KEY] = token
        }
    }
}
