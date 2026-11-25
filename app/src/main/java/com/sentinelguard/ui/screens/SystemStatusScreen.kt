package com.sentinelguard.ui.screens

import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import com.sentinelguard.ml.LlamaExplainerHolder
import com.sentinelguard.ml.ThreatClassifierHolder
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sentinelguard.keystore.KeystoreAttestationInfo
import com.sentinelguard.ui.BlocklistStats
import com.sentinelguard.ui.SystemStatus
import com.sentinelguard.ui.theme.*
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.atomic.AtomicInteger

// ─────────────────────────────────────────────────────────────────────────────
// Performance counters — thread-safe atomic singletons
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Lightweight in-process counters exposed to [SystemStatusScreen].
 * Incremented by the VPN/DNS/SMS layers and read on the UI thread.
 * AtomicInteger guarantees correct concurrent increments without locks.
 */
object PerfCounters {
    val packetsAnalysed    = AtomicInteger(0)
    val dnsQueriesInspected = AtomicInteger(0)
    val httpsInspected     = AtomicInteger(0)   // TLS SNI-inspected HTTPS connections
    val quicBlocked        = AtomicInteger(0)   // QUIC (UDP 443) packets dropped
    val smsScanned         = AtomicInteger(0)
}

// ─────────────────────────────────────────────────────────────────────────────
// Screen
// ─────────────────────────────────────────────────────────────────────────────

@Composable
fun SystemStatusScreen(
    systemStatus:  SystemStatus,
    keystoreInfo:  KeystoreAttestationInfo,
    keystoreReady: Boolean,
    blocklistStats: BlocklistStats
) {
    val scrollState = rememberScrollState()

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(ColorBackground)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(scrollState)
                .statusBarsPadding()
        ) {
            ScreenHeader(title = "System Status", subtitle = "Live module state")

            Column(
                modifier            = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp)
                    .padding(bottom = 32.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // ── Detection Layers ──────────────────────────────────────────
                StatusGroup(title = "Detection Layers") {
                    StatusRow(
                        icon    = Icons.Filled.Wifi,
                        label   = "VPN Tunnel",
                        active  = systemStatus.vpnTunnelActive
                    )
                    StatusDivider()
                    StatusRow(
                        icon    = Icons.Filled.Security,
                        label   = "DNS Inspector",
                        active  = systemStatus.dnsInspectorActive
                    )
                    StatusDivider()
                    StatusRow(
                        icon    = Icons.Filled.Sms,
                        label   = "SMS Monitor",
                        active  = systemStatus.smsMonitorActive
                    )
                    StatusDivider()
                    StatusRow(
                        icon    = Icons.Filled.Notifications,
                        label   = "Notification Listener",
                        active  = systemStatus.notificationListenerActive
                    )
                    StatusDivider()
                    StatusRow(
                        icon   = Icons.Filled.Psychology,
                        label  = "ML Classifier",
                        active = ThreatClassifierHolder.classifier?.isLoaded == true
                    )
                    StatusDivider()
                    StatusRow(
                        icon   = Icons.Filled.AutoAwesome,
                        label  = "Llama Explainer",
                        active = LlamaExplainerHolder.explainer?.isAvailable == true
                    )
                }

                // ── Keystore ──────────────────────────────────────────────────
                StatusGroup(title = "Hardware Keystore") {
                    InfoRow("Status",        if (keystoreReady) "Ready" else "Initialising",
                        if (keystoreReady) ColorStatusActive else ColorSeverityMedium)
                    StatusDivider()
                    BoolRow("StrongBox",     keystoreInfo.isStrongBox)
                    StatusDivider()
                    BoolRow("TEE Backed",    keystoreInfo.isTee || keystoreInfo.isStrongBox)
                    StatusDivider()
                    InfoRow("Algorithm",     keystoreInfo.keyAlgorithm.ifBlank { "—" })
                    StatusDivider()
                    InfoRow("Key Created",
                        if (keystoreInfo.createdAt > 0L)
                            shortDateFmt.format(Date(keystoreInfo.createdAt))
                        else "—"
                    )
                }

                // ── Blocklist ─────────────────────────────────────────────────
                StatusGroup(title = "Domain Blocklist") {
                    InfoRow(
                        label = "Domains Loaded",
                        value = "%,d".format(blocklistStats.totalDomains)
                    )
                    StatusDivider()
                    InfoRow(
                        label = "Last Updated",
                        value = if (blocklistStats.lastUpdated > 0L)
                            shortDateFmt.format(Date(blocklistStats.lastUpdated))
                        else "Never"
                    )
                    StatusDivider()
                    InfoRow(label = "Update Schedule", value = "Daily (Wi-Fi + charging)")
                }

                // ── Performance ───────────────────────────────────────────────
                StatusGroup(title = "Session Performance") {
                    InfoRow("Packets Analysed",    PerfCounters.packetsAnalysed.get().formatted())
                    StatusDivider()
                    InfoRow("DNS Queries",          PerfCounters.dnsQueriesInspected.get().formatted())
                    StatusDivider()
                    InfoRow("HTTPS (SNI Inspected)", PerfCounters.httpsInspected.get().formatted())
                    StatusDivider()
                    InfoRow("QUIC Blocked",         PerfCounters.quicBlocked.get().formatted())
                    StatusDivider()
                    InfoRow("SMS Messages Scanned", PerfCounters.smsScanned.get().formatted())
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared header composable (used by all three screens)
// ─────────────────────────────────────────────────────────────────────────────

@Composable
fun ScreenHeader(title: String, subtitle: String) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 20.dp)
            .padding(top = 28.dp, bottom = 20.dp)
    ) {
        Text(
            text          = title,
            fontSize      = 22.sp,
            fontWeight    = FontWeight.Bold,
            color         = Color.White,
            letterSpacing = 0.3.sp
        )
        Spacer(Modifier.height(3.dp))
        Text(
            text     = subtitle,
            fontSize = 12.sp,
            color    = ColorTextSecondary
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Group card
// ─────────────────────────────────────────────────────────────────────────────

@Composable
private fun StatusGroup(title: String, content: @Composable ColumnScope.() -> Unit) {
    Column {
        Text(
            text          = title.uppercase(),
            fontSize      = 10.sp,
            fontWeight    = FontWeight.SemiBold,
            color         = ColorTextSecondary,
            letterSpacing = 1.2.sp,
            modifier      = Modifier.padding(bottom = 8.dp, start = 2.dp)
        )
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape    = RoundedCornerShape(16.dp),
            color    = ColorSurface
        ) {
            Column(
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                content  = content
            )
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Row types
// ─────────────────────────────────────────────────────────────────────────────

@Composable
private fun StatusRow(icon: ImageVector, label: String, active: Boolean) {
    Row(
        modifier          = Modifier
            .fillMaxWidth()
            .padding(vertical = 13.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector        = icon,
            contentDescription = null,
            tint               = if (active) ColorAccent else ColorTextSecondary,
            modifier           = Modifier.size(18.dp)
        )
        Spacer(Modifier.width(12.dp))
        Text(
            text     = label,
            fontSize = 13.sp,
            color    = Color.White,
            modifier = Modifier.weight(1f)
        )
        StatusDot(active = active)
    }
}

@Composable
private fun BoolRow(label: String, value: Boolean) {
    InfoRow(
        label     = label,
        value     = if (value) "Yes" else "No",
        valueColor = if (value) ColorStatusActive else ColorSeverityHigh
    )
}

@Composable
private fun InfoRow(
    label:      String,
    value:      String,
    valueColor: Color = ColorTextSecondary
) {
    Row(
        modifier              = Modifier
            .fillMaxWidth()
            .padding(vertical = 13.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment     = Alignment.CenterVertically
    ) {
        Text(text = label, fontSize = 13.sp, color = Color.White)
        Text(text = value, fontSize = 12.sp, color = valueColor, fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun StatusDivider() {
    HorizontalDivider(color = ColorDivider, thickness = 0.5.dp)
}

@Composable
private fun StatusDot(active: Boolean) {
    Box(
        modifier = Modifier
            .size(8.dp)
            .clip(RoundedCornerShape(4.dp))
            .background(if (active) ColorStatusActive else ColorStatusInactive)
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

private val shortDateFmt = SimpleDateFormat("MMM dd, HH:mm", Locale.getDefault())

private fun Int.formatted(): String = when {
    this >= 1_000_000 -> "%.1fM".format(this / 1_000_000f)
    this >= 1_000     -> "%.1fK".format(this / 1_000f)
    else              -> toString()
}
