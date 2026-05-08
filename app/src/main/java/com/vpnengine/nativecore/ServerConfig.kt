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
 * Stores the ZeroTier Network ID so the user doesn't have to re-enter
 * it every time the app starts. Uses DataStore (not SharedPreferences) because
 * it is coroutine-based, type-safe, avoids ANRs from blocking I/O on the main
 * thread, and provides reactive Flow-based observation that integrates cleanly
 * with Jetpack Compose.
 *
 * ── Storage Details ──────────────────────────────────────────────────────
 *
 * DataStore writes to: /data/data/com.vpnengine.nativecore/files/datastore/vpn_settings.preferences_pb
 * Keys:
 *   - "network_id" → String (16-char hex ZeroTier network ID)
 *
 * ── Usage ────────────────────────────────────────────────────────────────
 *
 *   val config = ServerConfig(applicationContext)
 *   // Observe (reactive):
 *   config.networkId.collect { id -> ... }
 *   // Write:
 *   config.saveNetworkId("8056c2e21c000001")
 */
class ServerConfig(private val context: Context) {

    companion object {
        /** DataStore instance — lazily created, one per application. */
        private val Context.dataStore: DataStore<Preferences> by preferencesDataStore(
            name = "vpn_settings"
        )

        // ── Preference Keys ─────────────────────────────────────────────────
        private val NETWORK_ID_KEY = stringPreferencesKey("network_id")

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
                // Migrate to new key on next save
                legacyHost
            } else {
                ""
            }
        }
    }

    /**
     * Persist the ZeroTier Network ID to DataStore.
     *
     * This is a suspend function — call from a coroutine scope
     * (e.g., viewModelScope). The write is atomic and will not
     * block the calling thread.
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
}
