package com.vpnengine.nativecore.ui.theme

import androidx.compose.ui.graphics.Color

/**
 * Color palette for the VPN app's dark futuristic Material 3 theme.
 *
 * Design philosophy: Deep navy/black backgrounds with neon cyan and
 * purple accents create a high-tech, cyberpunk-inspired aesthetic.
 * The colors are chosen for maximum contrast on OLED screens while
 * remaining readable and accessible.
 */

// ── Primary ────────────────────────────────────────────────────────────
/** Electric cyan — primary accent for interactive elements and borders. */
val CyberCyan = Color(0xFF00E5FF)

/** Dimmer cyan for secondary text and subtle highlights. */
val CyberCyanDim = Color(0xFF0097A7)

// ── Status ─────────────────────────────────────────────────────────────
/** Neon green — indicates an active, healthy VPN connection. */
val CyberGreen = Color(0xFF00E676)

/** Dimmer green for secondary connected-state elements. */
val CyberGreenDim = Color(0xFF00C853)

/** Red — indicates errors, warnings, or permission denied. */
val CyberRed = Color(0xFFFF1744)

/** Amber — for warning states (reconnecting, degraded). */
val CyberAmber = Color(0xFFFFAB00)

// ── Secondary Accent ───────────────────────────────────────────────────
/** Neon purple — secondary accent for decorative elements and gradients. */
val CyberPurple = Color(0xFF7C4DFF)

/** Deep purple for gradient endpoints. */
val CyberPurpleDeep = Color(0xFF4A148C)

// ── Backgrounds ────────────────────────────────────────────────────────
/** Primary background — deep navy, nearly black. Optimized for OLED. */
val DarkBackground = Color(0xFF0B0D21)

/** Slightly lighter variant for cards and elevated surfaces. */
val DarkSurface = Color(0xFF1A1A2E)

/** Surface variant for bottom sheets and dialogs. */
val DarkSurfaceVariant = Color(0xFF16213E)

/** Outlined borders and dividers. */
val DarkOutline = Color(0xFF2A2A4A)

/** Muted text for secondary information. */
val DarkOnSurfaceVariant = Color(0xFF9E9EB8)

// ── Text ───────────────────────────────────────────────────────────────
/** Primary text color — high contrast white. */
val DarkOnBackground = Color(0xFFE8E8F0)

/** Secondary text — slightly dimmed for hierarchy. */
val DarkOnSurface = Color(0xFFB8B8D0)

// ── Gradient endpoints ─────────────────────────────────────────────────
/** Edge color for radial gradients (darker than center). */
val GradientEdge = Color(0xFF060816)
