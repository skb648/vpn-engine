package com.vpnengine.nativecore.ui.theme

import android.app.Activity
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

/**
 * Dark-only Material 3 color scheme for the VPN app.
 *
 * The app is designed exclusively for dark mode — a bright theme
 * would undermine the futuristic, OLED-optimized aesthetic.
 */
private val VpnDarkColorScheme = darkColorScheme(

    primary = CyberCyan,
    onPrimary = DarkBackground,
    primaryContainer = CyberCyanDim,
    onPrimaryContainer = DarkOnBackground,

    secondary = CyberPurple,
    onSecondary = DarkOnBackground,
    secondaryContainer = CyberPurpleDeep,
    onSecondaryContainer = DarkOnSurface,

    tertiary = CyberGreen,
    onTertiary = DarkBackground,
    tertiaryContainer = CyberGreenDim,
    onTertiaryContainer = DarkOnBackground,

    error = CyberRed,
    onError = DarkOnBackground,
    errorContainer = CyberRed.copy(alpha = 0.15f),
    onErrorContainer = CyberRed,

    background = DarkBackground,
    onBackground = DarkOnBackground,

    surface = DarkSurface,
    onSurface = DarkOnSurface,
    surfaceVariant = DarkSurfaceVariant,
    onSurfaceVariant = DarkOnSurfaceVariant,

    outline = DarkOutline,
    outlineVariant = DarkOutline.copy(alpha = 0.5f),

    inverseSurface = DarkOnSurface,
    inverseOnSurface = DarkSurface,
    inversePrimary = CyberCyanDim,

    scrim = GradientEdge
)

/**
 * Main theme composable for the VPN app.
 *
 * This is a dark-only theme — the app does not support light mode.
 * The futuristic UI requires a dark canvas for the neon glow effects
 * and OLED-friendly backgrounds.
 */
@Composable
fun VpnTheme(
    content: @Composable () -> Unit
) {
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = DarkBackground.toArgb()
            window.navigationBarColor = DarkBackground.toArgb()
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = false
            WindowCompat.getInsetsController(window, view).isAppearanceLightNavigationBars = false
        }
    }

    MaterialTheme(
        colorScheme = VpnDarkColorScheme,
        typography = VpnTypography,
        content = content
    )
}
