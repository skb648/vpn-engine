package com.vpnengine.nativecore

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.util.Log
import com.vpnengine.nativecore.R

/**
 * VpnNotificationHelper — Manages the foreground service notification
 *
 * Since Android 8.0 (API 26), a service running in the foreground MUST
 * show a persistent notification within 5 seconds of calling
 * startForeground(). If this deadline is missed, the system throws
 * AndroidRuntimeException and kills the app.
 *
 * Additionally, Android 13 (API 33) requires the POST_NOTIFICATIONS
 * runtime permission. However, foreground service notifications are
 * exempt from this permission requirement — they are always shown
 * regardless of the permission state. We still create the notification
 * channel at the IMPORTANCE_LOW level to avoid interrupting the user.
 *
 * This helper centralizes all notification logic so VpnTunnelService
 * doesn't need to deal with channel creation, pending intents, or
 * SDK version branching.
 */
object VpnNotificationHelper {

    private const val TAG = "VpnNotificationHelper"

    /** Notification channel ID — must be unique within the app. */
    private const val CHANNEL_ID = VpnTunnelService.NOTIFICATION_CHANNEL_ID

    /** Notification ID — must be consistent for foreground service updates. */
    private const val NOTIFICATION_ID = VpnTunnelService.NOTIFICATION_ID

    /** Request code for the stop-action PendingIntent. */
    private const val STOP_REQUEST_CODE = 2001

    /** Whether the notification channel has been created. */
    @Volatile
    private var channelCreated = false

    // ══════════════════════════════════════════════════════════════════════
    // Public API
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Show the foreground notification and start the service in the
     * foreground. This MUST be called within 5 seconds of
     * startForegroundService() on Android 8+.
     *
     * @param service The VpnTunnelService instance (also a Context).
     */
    fun showForegroundNotification(service: VpnTunnelService) {
        ensureChannelCreated(service)

        val notification = buildNotification(service, "Starting VPN tunnel...")

        // startForeground() makes the service foreground-visible to the
        // system, dramatically reducing the chance of being killed under
        // memory pressure. The notification is mandatory and cannot be
        // dismissed by the user while the service is foreground.
        // ── Phase 3 FIX: Proper foregroundServiceType for all API levels ──
        // Android 14+ (API 34) REQUIRES the foregroundServiceType parameter
        // in startForeground(). Without it, the app crashes with:
        //   "ForegroundServiceStartNotAllowedException"
        //
        // FOREGROUND_SERVICE_TYPE_SPECIAL_USE is required for VPN services
        // that don't fit standard categories (location, media, etc.).
        // This MUST match the android:foregroundServiceType in AndroidManifest.xml.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            // API 34+ (Android 14+): Must specify foregroundServiceType.
            // FOREGROUND_SERVICE_TYPE_SPECIAL_USE was added in API 34.
            // This MUST match android:foregroundServiceType="specialUse" in AndroidManifest.xml.
            service.startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // API 29-33 (Android 10-13): startForeground(id, notification, type) exists
            // but FOREGROUND_SERVICE_TYPE_SPECIAL_USE is NOT available.
            // Use 0 (no specific type) — the manifest doesn't declare a type on these APIs.
            @Suppress("DEPRECATION")
            service.startForeground(
                NOTIFICATION_ID,
                notification,
                0  // No specific foreground service type on API 29-33
            )
        } else {
            // API 21-28: No foregroundServiceType parameter
            service.startForeground(NOTIFICATION_ID, notification)
        }

        Log.d(TAG, "Foreground notification shown")
    }

    /**
     * Update the foreground notification with a new status message.
     * This is used to reflect state changes (connected, reconnecting, etc.)
     * without recreating the entire notification.
     *
     * @param context Any context (service or application).
     * @param message The new status text to display.
     */
    fun updateNotification(context: Context, message: String) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val notification = buildNotification(context, message)
        nm.notify(NOTIFICATION_ID, notification)
        Log.d(TAG, "Notification updated: $message")
    }

    /**
     * Cancel the foreground notification. This should be called after
     * stopForeground() to remove the notification from the status bar.
     *
     * @param context Any context.
     */
    fun cancelNotification(context: Context) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.cancel(NOTIFICATION_ID)
        Log.d(TAG, "Notification cancelled")
    }

    // ══════════════════════════════════════════════════════════════════════
    // Internal helpers
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Create the notification channel (required Android 8+).
     * This is idempotent — creating an existing channel is a no-op.
     *
     * We use IMPORTANCE_LOW so the notification doesn't make a sound
     * or peek onto the screen. It's just a persistent indicator.
     */
    private fun ensureChannelCreated(context: Context) {
        if (channelCreated) return

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "VPN Tunnel",
                NotificationManager.IMPORTANCE_LOW  // No sound, no peek
            ).apply {
                description = "Shows when VPN tunnel is active"
                setShowBadge(false)  // Don't show badge on launcher icon
                lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            }

            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(channel)
            channelCreated = true
            Log.d(TAG, "Notification channel created")
        }
    }

    /**
     * Build a notification with the current status message and a
     * "Disconnect" action.
     *
     * The "Disconnect" action sends an intent to VpnTunnelService
     * with ACTION_STOP, which triggers a clean shutdown.
     *
     * We use FLAG_IMMUTABLE for the PendingIntent on Android 12+
     * (required) and FLAG_UPDATE_CURRENT to update any existing
     * pending intent with the same request code.
     */
    private fun buildNotification(context: Context, message: String): Notification {
        // ── Content intent (tap notification → open app) ────────────
        val contentIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val contentFlags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        } else {
            PendingIntent.FLAG_UPDATE_CURRENT
        }
        val contentPendingIntent = PendingIntent.getActivity(
            context, 0, contentIntent, contentFlags
        )

        // ── Stop action intent ──────────────────────────────────────
        val stopIntent = Intent(context, VpnTunnelService::class.java).apply {
            action = VpnTunnelService.ACTION_STOP
        }

        val stopFlags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        } else {
            PendingIntent.FLAG_UPDATE_CURRENT
        }

        val stopPendingIntent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            // Android 8+: Use getForegroundService() for foreground service intents
            PendingIntent.getForegroundService(
                context,
                STOP_REQUEST_CODE,
                stopIntent,
                stopFlags
            )
        } else {
            @Suppress("DEPRECATION")
            PendingIntent.getService(
                context,
                STOP_REQUEST_CODE,
                stopIntent,
                stopFlags
            )
        }

        // ── Build the notification ──────────────────────────────────
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(context, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(context)
                .setPriority(Notification.PRIORITY_LOW)
        }

        return builder
            .setContentTitle("VPN Tunnel")
            .setContentText(message)
            .setSmallIcon(R.drawable.ic_vpn_notification)  // Custom VPN notification icon
            .setOngoing(true)          // User cannot swipe-dismiss
            .setShowWhen(false)        // Don't show timestamp
            .setCategory(Notification.CATEGORY_SERVICE)
            .setContentIntent(contentPendingIntent)  // Tap → open app
            .addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                "Disconnect",
                stopPendingIntent
            )
            .build()
    }
}
