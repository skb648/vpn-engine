package com.vpnengine.nativecore

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log

/**
 * VpnStopReceiver — BroadcastReceiver for stopping the VPN from outside the service
 *
 * This receiver provides an alternative entry-point for stopping the VPN
 * tunnel, which is useful for:
 *   - Quick-settings tile actions
 *   - App shortcut intents
 *   - Widget button clicks
 *   - External automation apps (Tasker, etc.)
 *
 * It simply forwards the stop intent to VpnTunnelService, which handles
 * the actual shutdown on its coroutine context.
 *
 * Note: The notification's "Disconnect" button sends the stop intent
 * directly to VpnTunnelService (via PendingIntent.getService), so this
 * receiver is NOT needed for notification actions. It exists as a
 * convenience for other UI entry points.
 */
class VpnStopReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "VpnStopReceiver"

        /** Action string for the broadcast. */
        const val ACTION_STOP_VPN = "com.vpnengine.nativecore.ACTION_STOP_VPN"
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_STOP_VPN) {
            Log.w(TAG, "Received unexpected action: ${intent.action}")
            return
        }

        Log.i(TAG, "Stop VPN broadcast received — forwarding to VpnTunnelService")

        // Forward the stop command to the VPN service. We use
        // startService (not startForegroundService) because the service
        // is already running in the foreground. startForegroundService
        // would require showing a new notification within 5 seconds,
        // which is unnecessary here.
        val stopIntent = Intent(context, VpnTunnelService::class.java).apply {
            action = VpnTunnelService.ACTION_STOP
        }

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                // Android 8+: Must use startForegroundService for background service start.
                // The service is already running foreground so this just delivers the intent.
                context.startForegroundService(stopIntent)
            } else {
                context.startService(stopIntent)
            }
        } catch (e: IllegalStateException) {
            // On Android 8+, this can happen if the app is in the
            // background and the service isn't running. In that case,
            // there's nothing to stop — the VPN is already down.
            Log.w(TAG, "Cannot start service (not running or background restriction): ${e.message}")
        }
    }
}
