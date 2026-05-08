package com.vpnengine.nativecore.ui.screen

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vpnengine.nativecore.AuthorizationStatus
import com.vpnengine.nativecore.VpnState
import com.vpnengine.nativecore.VpnStateHolder
import com.vpnengine.nativecore.VpnViewModel
import com.vpnengine.nativecore.ui.theme.*

/**
 * VpnScreen — ZeroTier P2P Mesh VPN UI
 *
 * PRODUCTION-READY (v6):
 *   - CRITICAL FIX: Animation crash fixed — using rememberInfiniteTransition
 *     instead of animateFloatAsState with infiniteRepeatable
 *   - ZeroTier Central API Token input for auto-authorization
 *   - Authorization status display with real-time feedback
 *   - All states properly handled with visual feedback
 *   - No dummy code — all real working functionality
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun VpnScreen(
    viewModel: VpnViewModel,
    onPermissionRequest: (android.content.Intent) -> Unit
) {

    val ctx = LocalContext.current
    var ztNodeId by remember { mutableStateOf("Tap Connect to Generate...") }
    var nodeIdCopied by remember { mutableStateOf(false) }

    // ── Advanced Auto-Refresh Loop for Node ID ──────────────────────────────
    LaunchedEffect(Unit) {
        while (true) {
            try {
                val engineNodeId = com.vpnengine.nativecore.ZtEngine.getNodeIdSafe()
                if (engineNodeId != 0L) {
                    val formatted = String.format(java.util.Locale.US, "%010x", engineNodeId)
                    if (formatted != ztNodeId) {
                        ztNodeId = formatted
                    }
                } else {
                    val f = java.io.File(ctx.filesDir, "zerotier/identity.public")
                    if (f.exists()) {
                        val idText = f.readText()
                        if (idText.length >= 10) {
                            val formatted = idText.take(10)
                            if (formatted != ztNodeId) {
                                ztNodeId = formatted
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                // Silently ignore
            }
            kotlinx.coroutines.delay(1000)
        }
    }

    // ── Copy feedback reset ─────────────────────────────────────────────────
    LaunchedEffect(nodeIdCopied) {
        if (nodeIdCopied) {
            kotlinx.coroutines.delay(2000)
            nodeIdCopied = false
        }
    }

    val vpnState by viewModel.vpnState.collectAsState()
    val trafficStats by viewModel.trafficStats.collectAsState()
    val assignedIPv4 by viewModel.assignedIPv4.collectAsState()
    val networkIdDisplay by viewModel.networkIdDisplay.collectAsState()
    val nodeId by viewModel.nodeId.collectAsState()
    val mode by viewModel.mode.collectAsState()
    val senderProxyAddress by viewModel.senderProxyAddress.collectAsState()
    val senderProxyPort by viewModel.senderProxyPort.collectAsState()
    val apiToken by viewModel.apiToken.collectAsState()
    val authStatus by viewModel.authStatus.collectAsState()

    val context = LocalContext.current

    // Collect permission events
    LaunchedEffect(Unit) {
        viewModel.permissionEvent.collect { intent ->
            onPermissionRequest(intent)
        }
    }

    // Collect snackbar events
    val snackbarHostState = remember { SnackbarHostState() }
    LaunchedEffect(Unit) {
        viewModel.snackBarEvent.collect { message ->
            snackbarHostState.showSnackbar(message, duration = SnackbarDuration.Long)
        }
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) },
        containerColor = Color(0xFF0A0E1A)
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState()),
            contentAlignment = Alignment.Center
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
                modifier = Modifier.padding(24.dp)
            ) {

                // ── ADVANCED NODE ID DISPLAY ──────────────────────────────
                Surface(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 8.dp),
                    shape = RoundedCornerShape(12.dp),
                    color = Color(0xFF111827).copy(alpha = 0.9f)
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.Center
                        ) {
                            Icon(
                                imageVector = Icons.Rounded.Fingerprint,
                                contentDescription = "Node ID",
                                tint = CyberCyan,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                text = "YOUR ZEROTIER NODE ID",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace,
                                    fontWeight = FontWeight.SemiBold,
                                    letterSpacing = 1.sp
                                ),
                                color = Color(0xFF9CA3AF)
                            )
                        }
                        Spacer(modifier = Modifier.height(8.dp))

                        Box(
                            modifier = Modifier
                                .combinedClickable(
                                    onClick = { /* no-op */ },
                                    onLongClick = {
                                        if (ztNodeId != "Tap Connect to Generate...") {
                                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE)
                                                    as ClipboardManager
                                            val clip = ClipData.newPlainText("ZeroTier Node ID", ztNodeId)
                                            clipboard.setPrimaryClip(clip)
                                            nodeIdCopied = true
                                        }
                                    }
                                )
                                .padding(8.dp)
                        ) {
                            Text(
                                text = ztNodeId,
                                style = MaterialTheme.typography.headlineSmall.copy(
                                    fontWeight = FontWeight.Bold,
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 18.sp
                                ),
                                color = Color.White,
                                textAlign = TextAlign.Center
                            )
                        }

                        AnimatedVisibility(
                            visible = nodeIdCopied,
                            enter = fadeIn() + expandVertically(),
                            exit = fadeOut() + shrinkVertically()
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.Center
                            ) {
                                Icon(
                                    imageVector = Icons.Rounded.CheckCircle,
                                    contentDescription = null,
                                    tint = CyberGreen,
                                    modifier = Modifier.size(14.dp)
                                )
                                Spacer(modifier = Modifier.width(4.dp))
                                Text(
                                    text = "Copied to clipboard!",
                                    style = MaterialTheme.typography.labelSmall.copy(
                                        fontFamily = FontFamily.Monospace
                                    ),
                                    color = CyberGreen
                                )
                            }
                        }

                        if (!nodeIdCopied && ztNodeId != "Tap Connect to Generate...") {
                            Text(
                                text = "Long press to copy",
                                style = MaterialTheme.typography.labelSmall.copy(
                                    fontFamily = FontFamily.Monospace
                                ),
                                color = Color(0xFF6B7280),
                                modifier = Modifier.padding(top = 2.dp)
                            )
                        }

                        // ── Authorization Status ──────────────────────────
                        AuthStatusDisplay(
                            authStatus = authStatus,
                            vpnState = vpnState
                        )
                    }
                }

                // ── App Title ───────────────────────────────────────────
                Text(
                    text = "ZT P2P Mesh",
                    style = MaterialTheme.typography.headlineMedium.copy(
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    ),
                    color = CyberCyan
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "ZeroTier Encrypted Mesh VPN",
                    style = MaterialTheme.typography.bodySmall,
                    color = Color(0xFF6B7280)
                )

                // ── SDK Warning Banner ─────────────────────────────────────
                val showSdkBanner = remember(vpnState) {
                    (vpnState as? VpnState.Error)?.message?.let { msg ->
                        msg.contains("ZeroTier SDK", ignoreCase = true) ||
                        msg.contains("zts_init", ignoreCase = true) ||
                        msg.contains("libzt", ignoreCase = true) ||
                        msg.contains("not loaded", ignoreCase = true) ||
                        msg.contains("not properly linked", ignoreCase = true)
                    } ?: false
                }
                if (showSdkBanner) {
                    Spacer(modifier = Modifier.height(12.dp))
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(8.dp),
                        color = CyberRed.copy(alpha = 0.15f)
                    ) {
                        Row(
                            modifier = Modifier.padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = Icons.Rounded.Warning,
                                contentDescription = "Warning",
                                tint = CyberRed,
                                modifier = Modifier.size(20.dp)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = "ZeroTier SDK not found. Build with libzt to enable VPN.",
                                style = MaterialTheme.typography.bodySmall.copy(
                                    fontFamily = FontFamily.Monospace
                                ),
                                color = CyberRed
                            )
                        }
                    }
                }

                // ── Mode Toggle ─────────────────────────────────────────
                Spacer(modifier = Modifier.height(20.dp))
                ModeToggle(
                    mode = mode,
                    onModeChange = { viewModel.setMode(it) },
                    isConnected = vpnState is VpnState.Connected ||
                            vpnState is VpnState.InitializingNode ||
                            vpnState is VpnState.P2pHandshake ||
                            vpnState is VpnState.JoiningMesh ||
                            vpnState is VpnState.Authenticating ||
                            vpnState is VpnState.WaitingAuthorization ||
                            vpnState is VpnState.Reconnecting
                )

                Spacer(modifier = Modifier.height(32.dp))

                // ── Animated Power Button ───────────────────────────────
                P2PMeshToggle(
                    vpnState = vpnState,
                    onToggle = {
                        when (vpnState) {
                            is VpnState.Disconnected,
                            is VpnState.Error -> viewModel.connect()
                            is VpnState.Connected -> viewModel.disconnect()
                            is VpnState.Connecting,
                            is VpnState.InitializingNode,
                            is VpnState.P2pHandshake,
                            is VpnState.JoiningMesh,
                            is VpnState.Authenticating,
                            is VpnState.WaitingAuthorization,
                            is VpnState.Reconnecting -> viewModel.disconnect()
                        }
                    }
                )

                Spacer(modifier = Modifier.height(24.dp))

                // ── Status Text ─────────────────────────────────────────
                StatusLabel(vpnState = vpnState)

                Spacer(modifier = Modifier.height(24.dp))

                // ── Connection Details (when connected) ─────────────────
                AnimatedVisibility(
                    visible = vpnState is VpnState.Connected,
                    enter = fadeIn() + expandVertically(),
                    exit = fadeOut() + shrinkVertically()
                ) {
                    if (mode == VpnStateHolder.VpnMode.SENDER) {
                        SenderDetailsPanel(
                            proxyAddress = senderProxyAddress,
                            proxyPort = senderProxyPort,
                            networkId = networkIdDisplay,
                            nodeId = nodeId
                        )
                    } else {
                        MeshDetailsPanel(
                            assignedIPv4 = assignedIPv4,
                            networkId = networkIdDisplay,
                            nodeId = nodeId,
                            trafficStats = trafficStats
                        )
                    }
                }

                // ── Network ID Display ──────────────────────────────────
                if (vpnState !is VpnState.Connected) {
                    Spacer(modifier = Modifier.height(16.dp))
                    NetworkIdDisplay(
                        networkId = networkIdDisplay,
                        onNetworkIdChange = { viewModel.updateNetworkId(it) },
                        isEditing = vpnState is VpnState.Disconnected || vpnState is VpnState.Error
                    )
                }

                // ── ZeroTier Central API Token ──────────────────────────
                Spacer(modifier = Modifier.height(16.dp))
                ApiTokenDisplay(
                    apiToken = apiToken,
                    onTokenChange = { viewModel.updateApiToken(it) },
                    isEditing = vpnState is VpnState.Disconnected || vpnState is VpnState.Error,
                    onCheckAuth = { viewModel.checkAuthorization() },
                    showCheckButton = vpnState is VpnState.WaitingAuthorization ||
                            vpnState is VpnState.Authenticating ||
                            vpnState is VpnState.JoiningMesh ||
                            vpnState is VpnState.Connected
                )
            }
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Authorization Status Display
// ══════════════════════════════════════════════════════════════════════════════

@Composable
fun AuthStatusDisplay(
    authStatus: AuthorizationStatus?,
    vpnState: VpnState
) {
    if (authStatus == null) return
    if (vpnState !is VpnState.WaitingAuthorization &&
        vpnState !is VpnState.Authenticating &&
        vpnState !is VpnState.JoiningMesh &&
        vpnState !is VpnState.Connected
    ) return

    val (bgColor, textColor, icon) = when (authStatus) {
        is AuthorizationStatus.Authorized -> Triple(
            Color(0xFF059669).copy(alpha = 0.15f), Color(0xFF34D399), Icons.Rounded.CheckCircle)
        is AuthorizationStatus.NotAuthorized -> Triple(
            Color(0xFFDC2626).copy(alpha = 0.15f), Color(0xFFF87171), Icons.Rounded.Error)
        is AuthorizationStatus.Pending -> Triple(
            Color(0xFFD97706).copy(alpha = 0.15f), Color(0xFFFBBF24), Icons.Rounded.HourglassTop)
        is AuthorizationStatus.Error -> Triple(
            Color(0xFF6B7280).copy(alpha = 0.15f), Color(0xFF9CA3AF), Icons.Rounded.Info)
    }

    Spacer(modifier = Modifier.height(8.dp))
    Surface(
        shape = RoundedCornerShape(8.dp),
        color = bgColor
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = textColor,
                modifier = Modifier.size(16.dp)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = when (authStatus) {
                    is AuthorizationStatus.Authorized -> authStatus.message
                    is AuthorizationStatus.NotAuthorized -> authStatus.message
                    is AuthorizationStatus.Pending -> authStatus.message
                    is AuthorizationStatus.Error -> authStatus.message
                },
                style = MaterialTheme.typography.labelSmall.copy(
                    fontFamily = FontFamily.Monospace
                ),
                color = textColor
            )
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Mode Toggle
// ══════════════════════════════════════════════════════════════════════════════

@Composable
fun ModeToggle(
    mode: VpnStateHolder.VpnMode,
    onModeChange: (VpnStateHolder.VpnMode) -> Unit,
    isConnected: Boolean
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        color = Color(0xFF111827).copy(alpha = 0.8f)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(4.dp),
            horizontalArrangement = Arrangement.Center
        ) {
            ModeTab(
                label = "Receiver",
                subtitle = "Use internet from peer",
                icon = Icons.Rounded.Download,
                isSelected = mode == VpnStateHolder.VpnMode.RECEIVER,
                onClick = { onModeChange(VpnStateHolder.VpnMode.RECEIVER) },
                enabled = !isConnected,
                modifier = Modifier.weight(1f)
            )

            Spacer(modifier = Modifier.width(4.dp))

            ModeTab(
                label = "Sender",
                subtitle = "Share internet to peers",
                icon = Icons.Rounded.Upload,
                isSelected = mode == VpnStateHolder.VpnMode.SENDER,
                onClick = { onModeChange(VpnStateHolder.VpnMode.SENDER) },
                enabled = !isConnected,
                modifier = Modifier.weight(1f)
            )
        }
    }
}

@Composable
fun ModeTab(
    label: String,
    subtitle: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    isSelected: Boolean,
    onClick: () -> Unit,
    enabled: Boolean,
    modifier: Modifier = Modifier
) {
    val bgColor by animateColorAsState(
        targetValue = if (isSelected) CyberCyan.copy(alpha = 0.15f) else Color.Transparent,
        animationSpec = tween(300),
        label = "mode_bg"
    )
    val textColor by animateColorAsState(
        targetValue = if (isSelected) CyberCyan else Color(0xFF6B7280),
        animationSpec = tween(300),
        label = "mode_text"
    )

    Surface(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .then(if (enabled) Modifier.clickable { onClick() } else Modifier),
        color = bgColor,
        shape = RoundedCornerShape(8.dp)
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.padding(12.dp)
        ) {
            Icon(
                imageVector = icon,
                contentDescription = label,
                tint = if (enabled) textColor else Color(0xFF374151),
                modifier = Modifier.size(20.dp)
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium.copy(
                    fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                    fontFamily = FontFamily.Monospace
                ),
                color = if (enabled) textColor else Color(0xFF374151)
            )
            Text(
                text = subtitle,
                style = MaterialTheme.typography.labelSmall.copy(
                    fontFamily = FontFamily.Monospace
                ),
                color = if (enabled) textColor.copy(alpha = 0.6f) else Color(0xFF374151),
                fontSize = 9.sp
            )
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// P2P Mesh Toggle Button
// ══════════════════════════════════════════════════════════════════════════════

@Composable
fun P2PMeshToggle(
    vpnState: VpnState,
    onToggle: () -> Unit
) {
    val isConnected = vpnState is VpnState.Connected
    val isConnecting = vpnState is VpnState.Connecting ||
            vpnState is VpnState.InitializingNode ||
            vpnState is VpnState.P2pHandshake ||
            vpnState is VpnState.JoiningMesh ||
            vpnState is VpnState.Authenticating ||
            vpnState is VpnState.WaitingAuthorization ||
            vpnState is VpnState.Reconnecting

    // Ring color animation
    val ringColor by animateColorAsState(
        targetValue = when (vpnState) {
            is VpnState.Connected -> CyberGreen
            is VpnState.P2pHandshake -> Color(0xFF00BCD4)
            is VpnState.Authenticating -> Color(0xFFAB47BC)
            is VpnState.Connecting,
            is VpnState.InitializingNode,
            is VpnState.JoiningMesh,
            is VpnState.WaitingAuthorization -> CyberCyan
            is VpnState.Reconnecting -> Color(0xFFFF9800)
            is VpnState.Error -> CyberRed
            is VpnState.Disconnected -> Color(0xFF2A2D3E)
        },
        animationSpec = tween(800),
        label = "ring_color"
    )

    // CRITICAL FIX: Use rememberInfiniteTransition instead of animateFloatAsState
    // with infiniteRepeatable to prevent animation crashes.
    // The pulseScale only animates when connecting.
    val infiniteTransition = rememberInfiniteTransition(label = "pulse")
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = if (isConnecting) 1.08f else 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(1000, easing = EaseInOutCubic),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulse_scale"
    )

    // Rotating scan ring when connecting
    val scanAngle by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(3000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "scan_angle"
    )

    Box(
        contentAlignment = Alignment.Center,
        modifier = Modifier
            .size(200.dp)
            .clip(RoundedCornerShape(100.dp))
            .clickable { onToggle() }
    ) {
        // Outer rotating ring (only when connecting)
        if (isConnecting) {
            Canvas(modifier = Modifier.size(200.dp)) {
                rotate(scanAngle) {
                    drawArc(
                        color = ringColor.copy(alpha = 0.6f),
                        startAngle = 0f,
                        sweepAngle = 120f,
                        useCenter = false,
                        topLeft = Offset(10f, 10f),
                        size = Size(size.width - 20f, size.height - 20f),
                        style = Stroke(width = 3.dp.toPx(), cap = StrokeCap.Round)
                    )
                }
            }
        }

        // Main ring with pulse animation
        val scaleModifier = if (isConnecting) {
            Modifier
                .size(180.dp)
                .scale(pulseScale)
        } else {
            Modifier.size(180.dp)
        }
        Canvas(modifier = scaleModifier) {
            drawCircle(
                color = ringColor,
                radius = (size.minDimension / 2) - 6.dp.toPx(),
                style = Stroke(width = 4.dp.toPx())
            )
        }

        // Inner circle with icon
        Surface(
            modifier = Modifier.size(140.dp),
            shape = RoundedCornerShape(100.dp),
            color = Color(0xFF111827),
            tonalElevation = 4.dp
        ) {
            Box(contentAlignment = Alignment.Center) {
                Icon(
                    imageVector = when (vpnState) {
                        is VpnState.Connected -> Icons.Rounded.Shield
                        is VpnState.InitializingNode -> Icons.Rounded.Settings
                        is VpnState.P2pHandshake -> Icons.Rounded.CompareArrows
                        is VpnState.JoiningMesh -> Icons.Rounded.Sync
                        is VpnState.Authenticating -> Icons.Rounded.VerifiedUser
                        is VpnState.WaitingAuthorization -> Icons.Rounded.HourglassTop
                        is VpnState.Reconnecting -> Icons.Rounded.Refresh
                        is VpnState.Connecting -> Icons.Rounded.Sync
                        is VpnState.Error -> Icons.Rounded.Error
                        is VpnState.Disconnected -> Icons.Rounded.PowerSettingsNew
                    },
                    contentDescription = if (isConnected) "Disconnect" else "Connect to P2P Mesh",
                    modifier = Modifier.size(52.dp),
                    tint = when (vpnState) {
                        is VpnState.Connected -> CyberGreen
                        is VpnState.P2pHandshake -> Color(0xFF00BCD4)
                        is VpnState.Authenticating -> Color(0xFFAB47BC)
                        is VpnState.Connecting,
                        is VpnState.InitializingNode,
                        is VpnState.JoiningMesh,
                        is VpnState.WaitingAuthorization -> CyberCyan
                        is VpnState.Reconnecting -> Color(0xFFFF9800)
                        is VpnState.Error -> CyberRed
                        is VpnState.Disconnected -> Color(0xFF4B5563)
                    }
                )
                if (isConnecting) {
                    val spinAngle by infiniteTransition.animateFloat(
                        initialValue = 0f,
                        targetValue = 360f,
                        animationSpec = infiniteRepeatable(
                            animation = tween(1500, easing = LinearEasing),
                            repeatMode = RepeatMode.Restart
                        ),
                        label = "spin"
                    )
                    Canvas(modifier = Modifier.size(140.dp)) {
                        rotate(spinAngle) {
                            drawArc(
                                color = ringColor.copy(alpha = 0.3f),
                                startAngle = 0f,
                                sweepAngle = 60f,
                                useCenter = false,
                                topLeft = Offset(8f, 8f),
                                size = Size(size.width - 16f, size.height - 16f),
                                style = Stroke(width = 2.dp.toPx(), cap = StrokeCap.Round)
                            )
                        }
                    }
                }
            }
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Status Label
// ══════════════════════════════════════════════════════════════════════════════

@Composable
fun StatusLabel(vpnState: VpnState) {
    val (text, color) = when (vpnState) {
        is VpnState.Disconnected -> "Tap to join mesh" to Color(0xFF6B7280)
        is VpnState.InitializingNode -> "Initializing ZeroTier node..." to CyberCyan
        is VpnState.P2pHandshake -> "P2P Handshake (UDP hole punching)..." to Color(0xFF00BCD4)
        is VpnState.JoiningMesh -> "Joining P2P mesh..." to CyberCyan
        is VpnState.Authenticating -> "Authenticating with network..." to Color(0xFFAB47BC)
        is VpnState.WaitingAuthorization -> "Waiting for network authorization..." to Color(0xFFE5A000)
        is VpnState.Connected -> "Connected to mesh" to CyberGreen
        is VpnState.Reconnecting -> "Reconnecting (attempt ${vpnState.attempt}/${vpnState.maxAttempts})..." to Color(0xFFFF9800)
        is VpnState.Error -> "Connection failed" to CyberRed
        is VpnState.Connecting -> "Connecting..." to CyberCyan
    }

    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.Center
    ) {
        if (vpnState is VpnState.Connected) {
            Canvas(modifier = Modifier.size(8.dp)) {
                drawCircle(color = CyberGreen)
            }
            Spacer(modifier = Modifier.width(8.dp))
        }
        if (vpnState is VpnState.WaitingAuthorization || vpnState is VpnState.Authenticating) {
            Canvas(modifier = Modifier.size(8.dp)) {
                drawCircle(color = Color(0xFFE5A000))
            }
            Spacer(modifier = Modifier.width(8.dp))
        }
        if (vpnState is VpnState.Reconnecting) {
            Canvas(modifier = Modifier.size(8.dp)) {
                drawCircle(color = Color(0xFFFF9800))
            }
            Spacer(modifier = Modifier.width(8.dp))
        }
        Text(
            text = text,
            style = MaterialTheme.typography.bodyLarge.copy(
                fontWeight = FontWeight.Medium,
                fontFamily = FontFamily.Monospace
            ),
            color = color
        )
    }

    if (vpnState is VpnState.WaitingAuthorization) {
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = "Authorize this node at my.zerotier.com",
            style = MaterialTheme.typography.bodySmall,
            color = Color(0xFFE5A000).copy(alpha = 0.7f),
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(horizontal = 32.dp)
        )
    }
    if (vpnState is VpnState.P2pHandshake) {
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = "Negotiating direct connection through your network...",
            style = MaterialTheme.typography.bodySmall,
            color = Color(0xFF00BCD4).copy(alpha = 0.7f),
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(horizontal = 32.dp)
        )
    }
    if (vpnState is VpnState.Authenticating) {
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = "Network controller is verifying your node...",
            style = MaterialTheme.typography.bodySmall,
            color = Color(0xFFAB47BC).copy(alpha = 0.7f),
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(horizontal = 32.dp)
        )
    }
    if (vpnState is VpnState.Reconnecting) {
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = "Connection lost — retrying with exponential backoff...",
            style = MaterialTheme.typography.bodySmall,
            color = Color(0xFFFF9800).copy(alpha = 0.7f),
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(horizontal = 32.dp)
        )
    }
    if (vpnState is VpnState.Error) {
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = vpnState.message,
            style = MaterialTheme.typography.bodySmall,
            color = CyberRed.copy(alpha = 0.7f),
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(horizontal = 32.dp)
        )
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Mesh Details Panel
// ══════════════════════════════════════════════════════════════════════════════

@Composable
fun MeshDetailsPanel(
    assignedIPv4: String,
    networkId: String,
    nodeId: Long,
    trafficStats: VpnStateHolder.TrafficStats
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        color = Color(0xFF111827).copy(alpha = 0.8f)
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Rounded.Shield,
                    contentDescription = null,
                    tint = CyberGreen,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "Mesh Connection",
                    style = MaterialTheme.typography.titleMedium.copy(
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    ),
                    color = CyberGreen
                )
            }

            HorizontalDivider(color = Color(0xFF1F2937))

            DetailRow("Virtual IP", assignedIPv4.ifBlank { "—" })
            DetailRow("Network ID", networkId)
            if (nodeId != 0L) {
                DetailRow("Node ID", String.format(java.util.Locale.US, "%010x", nodeId))
            }
            DetailRow("Download", formatBytes(trafficStats.bytesIn))
            DetailRow("Upload", formatBytes(trafficStats.bytesOut))
            DetailRow("Packets In", trafficStats.packetsIn.toString())
            DetailRow("Packets Out", trafficStats.packetsOut.toString())
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Sender Details Panel
// ══════════════════════════════════════════════════════════════════════════════

@Composable
fun SenderDetailsPanel(
    proxyAddress: String,
    proxyPort: Int,
    networkId: String,
    nodeId: Long
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        color = Color(0xFF111827).copy(alpha = 0.8f)
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Rounded.Upload,
                    contentDescription = null,
                    tint = CyberGreen,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "SOCKS5 Proxy",
                    style = MaterialTheme.typography.titleMedium.copy(
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace
                    ),
                    color = CyberGreen
                )
            }

            HorizontalDivider(color = Color(0xFF1F2937))

            DetailRow("Proxy Address", "$proxyAddress:$proxyPort")
            DetailRow("Network ID", networkId)
            if (nodeId != 0L) {
                DetailRow("Node ID", String.format(java.util.Locale.US, "%010x", nodeId))
            }

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = "Other peers can configure this address as their SOCKS5 proxy to access the internet through this device.",
                style = MaterialTheme.typography.bodySmall.copy(
                    fontFamily = FontFamily.Monospace
                ),
                color = Color(0xFF9CA3AF),
                textAlign = TextAlign.Center
            )
        }
    }
}

@Composable
fun DetailRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
            color = Color(0xFF9CA3AF)
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall.copy(
                fontWeight = FontWeight.Medium,
                fontFamily = FontFamily.Monospace
            ),
            color = Color.White
        )
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Network ID Display
// ══════════════════════════════════════════════════════════════════════════════

@Composable
fun NetworkIdDisplay(
    networkId: String,
    onNetworkIdChange: (String) -> Unit,
    isEditing: Boolean
) {
    var isEditingNow by remember { mutableStateOf(false) }
    var editValue by remember(networkId) { mutableStateOf(networkId) }

    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        color = Color(0xFF111827).copy(alpha = 0.6f)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(
                    imageVector = Icons.Rounded.Dns,
                    contentDescription = null,
                    tint = Color(0xFF6B7280),
                    modifier = Modifier.size(16.dp)
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = "Network ID",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace
                    ),
                    color = Color(0xFF6B7280)
                )
                Spacer(modifier = Modifier.weight(1f))
                if (isEditing && !isEditingNow) {
                    TextButton(onClick = { isEditingNow = true }) {
                        Text(
                            text = "Edit",
                            style = MaterialTheme.typography.labelSmall,
                            color = CyberCyan
                        )
                    }
                }
            }

            if (isEditingNow) {
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = editValue,
                    onValueChange = { newVal ->
                        val filtered = newVal.trim().lowercase()
                            .filter { it in '0'..'9' || it in 'a'..'f' }
                            .take(16)
                        editValue = filtered
                    },
                    label = { Text("16-char hex ID") },
                    placeholder = { Text("e.g. 8056c2e21c000001") },
                    supportingText = {
                        if (editValue.isNotBlank() && editValue.length != 16) {
                            Text(
                                "${editValue.length}/16 characters",
                                color = CyberRed
                            )
                        } else if (editValue.length == 16) {
                            Text(
                                "16/16 characters",
                                color = CyberGreen
                            )
                        } else {
                            Text("16 hex characters required")
                        }
                    },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(8.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = CyberCyan,
                        unfocusedBorderColor = Color(0xFF374151),
                        focusedLabelColor = CyberCyan,
                        cursorColor = CyberCyan
                    )
                )
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    TextButton(onClick = {
                        isEditingNow = false
                        editValue = networkId
                    }) {
                        Text("Cancel", color = Color(0xFF6B7280))
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Button(
                        onClick = {
                            if (editValue.length == 16) {
                                onNetworkIdChange(editValue)
                                isEditingNow = false
                            }
                        },
                        enabled = editValue.length == 16,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = CyberCyan,
                            disabledContainerColor = Color(0xFF374151)
                        )
                    ) {
                        Text("Save", color = if (editValue.length == 16) Color.Black else Color(0xFF6B7280))
                    }
                }
            } else {
                Text(
                    text = networkId.ifBlank { "Not set — tap Edit to enter Network ID" },
                    style = MaterialTheme.typography.bodyMedium.copy(
                        fontWeight = FontWeight.Medium,
                        fontFamily = FontFamily.Monospace
                    ),
                    color = if (networkId.isBlank()) Color(0xFF6B7280) else Color.White,
                    modifier = Modifier.padding(top = 4.dp)
                )
            }
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// ZeroTier Central API Token Display
// ══════════════════════════════════════════════════════════════════════════════

@Composable
fun ApiTokenDisplay(
    apiToken: String,
    onTokenChange: (String) -> Unit,
    isEditing: Boolean,
    onCheckAuth: () -> Unit,
    showCheckButton: Boolean
) {
    var isEditingNow by remember { mutableStateOf(false) }
    var editValue by remember(apiToken) { mutableStateOf(apiToken) }
    var isVisible by remember { mutableStateOf(false) }

    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        color = Color(0xFF111827).copy(alpha = 0.6f)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(
                    imageVector = Icons.Rounded.Key,
                    contentDescription = null,
                    tint = Color(0xFF6B7280),
                    modifier = Modifier.size(16.dp)
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = "ZeroTier Central API Token",
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontFamily = FontFamily.Monospace
                    ),
                    color = Color(0xFF6B7280)
                )
                Spacer(modifier = Modifier.weight(1f))
                if (isEditing && !isEditingNow) {
                    TextButton(onClick = { isEditingNow = true }) {
                        Text(
                            text = if (apiToken.isNotBlank()) "Edit" else "Add",
                            style = MaterialTheme.typography.labelSmall,
                            color = CyberCyan
                        )
                    }
                }
            }

            if (isEditingNow) {
                Spacer(modifier = Modifier.height(8.dp))
                OutlinedTextField(
                    value = editValue,
                    onValueChange = { editValue = it },
                    label = { Text("API Token (optional)") },
                    placeholder = { Text("Paste token from my.zerotier.com/account") },
                    supportingText = {
                        Text(
                            "Enables auto-authorization. Get token at my.zerotier.com/account#tokens",
                            color = Color(0xFF6B7280)
                        )
                    },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(8.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = CyberCyan,
                        unfocusedBorderColor = Color(0xFF374151),
                        focusedLabelColor = CyberCyan,
                        cursorColor = CyberCyan
                    )
                )
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    TextButton(onClick = {
                        isEditingNow = false
                        editValue = apiToken
                    }) {
                        Text("Cancel", color = Color(0xFF6B7280))
                    }
                    Spacer(modifier = Modifier.width(8.dp))
                    Button(
                        onClick = {
                            onTokenChange(editValue)
                            isEditingNow = false
                        },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = CyberCyan
                        )
                    ) {
                        Text("Save", color = Color.Black)
                    }
                }
            } else {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = if (apiToken.isNotBlank()) {
                            if (isVisible) apiToken else "••••••••" + apiToken.takeLast(4)
                        } else {
                            "Not set — add token for auto-authorization"
                        },
                        style = MaterialTheme.typography.bodyMedium.copy(
                            fontWeight = FontWeight.Medium,
                            fontFamily = FontFamily.Monospace
                        ),
                        color = if (apiToken.isBlank()) Color(0xFF6B7280) else Color.White,
                        modifier = Modifier.weight(1f)
                    )
                    if (apiToken.isNotBlank()) {
                        IconButton(onClick = { isVisible = !isVisible }) {
                            Icon(
                                imageVector = if (isVisible) Icons.Rounded.VisibilityOff else Icons.Rounded.Visibility,
                                contentDescription = if (isVisible) "Hide" else "Show",
                                tint = Color(0xFF6B7280),
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    }
                }
            }

            // Check Authorization button
            if (showCheckButton) {
                Spacer(modifier = Modifier.height(8.dp))
                Button(
                    onClick = onCheckAuth,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color(0xFF059669)
                    ),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Icon(
                        imageVector = Icons.Rounded.VerifiedUser,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        "Check / Authorize Node",
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Medium
                    )
                }
            }
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Utility
// ══════════════════════════════════════════════════════════════════════════════

private fun formatBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    if (bytes < 1024 * 1024) return String.format(java.util.Locale.US, "%.1f KB", bytes / 1024.0)
    if (bytes < 1024 * 1024 * 1024) return String.format(java.util.Locale.US, "%.1f MB", bytes / (1024.0 * 1024))
    return String.format(java.util.Locale.US, "%.1f GB", bytes / (1024.0 * 1024 * 1024))
}
