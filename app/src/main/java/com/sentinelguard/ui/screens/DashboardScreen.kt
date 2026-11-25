package com.sentinelguard.ui.screens

import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.GppGood
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.TravelExplore
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sentinelguard.keystore.KeystoreAttestationInfo
import com.sentinelguard.ui.RemediationAdvisor
import com.sentinelguard.ui.ThreatCounts
import com.sentinelguard.ui.theme.*
import com.sentinelguard.ui.screens.PerfCounters
import com.sentinelguard.vpn.ThreatEvent
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun DashboardScreen(
    vpnActive:     Boolean,
    onToggle:      (Boolean) -> Unit,
    threatCounts:  ThreatCounts,
    recentThreats: List<ThreatEvent>,
    keystoreInfo:  KeystoreAttestationInfo,
    keystoreReady: Boolean
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
                .padding(horizontal = 20.dp)
                .padding(bottom = 24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(Modifier.height(28.dp))

            // ── App name ──────────────────────────────────────────────────────
            Text(
                text          = "SentinelGuard",
                fontSize      = 26.sp,
                fontWeight    = FontWeight.Bold,
                color         = Color.White,
                letterSpacing = 0.5.sp
            )
            Text(
                text          = "On-Device AI Threat Protection",
                fontSize      = 12.sp,
                color         = ColorTextSecondary,
                letterSpacing = 0.3.sp
            )

            Spacer(Modifier.height(36.dp))

            // ── Animated shield ───────────────────────────────────────────────
            AnimatedShield(active = vpnActive)

            Spacer(Modifier.height(16.dp))

            // ── Status label ──────────────────────────────────────────────────
            AnimatedContent(
                targetState = vpnActive,
                transitionSpec = {
                    fadeIn(tween(300)) togetherWith fadeOut(tween(200))
                },
                label = "status_text"
            ) { active ->
                Text(
                    text          = if (active) "PROTECTED" else "INACTIVE",
                    fontSize      = 13.sp,
                    fontWeight    = FontWeight.Bold,
                    color         = if (active) ColorStatusActive else ColorTextSecondary,
                    letterSpacing = 2.sp
                )
            }

            Spacer(Modifier.height(28.dp))

            // ── VPN toggle card ───────────────────────────────────────────────
            VpnToggleCard(active = vpnActive, onToggle = onToggle)

            Spacer(Modifier.height(20.dp))

            // ── Threat counter row ────────────────────────────────────────────
            ThreatCounterRow(counts = threatCounts)

            Spacer(Modifier.height(20.dp))

            // ── Recent threats ────────────────────────────────────────────────
            RecentThreatsSection(threats = recentThreats)

            Spacer(Modifier.height(20.dp))

            // ── Keystore status ───────────────────────────────────────────────
            KeystoreStatusChip(ready = keystoreReady, info = keystoreInfo)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Animated shield — double-ring glow on active
// ─────────────────────────────────────────────────────────────────────────────

@Composable
private fun AnimatedShield(active: Boolean) {
    val infiniteTransition = rememberInfiniteTransition(label = "shield_pulse")

    val scale by infiniteTransition.animateFloat(
        initialValue  = 1.0f,
        targetValue   = if (active) 1.07f else 1.0f,
        animationSpec = infiniteRepeatable(
            animation  = tween(1200, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "shield_scale"
    )

    val outerGlowAlpha by infiniteTransition.animateFloat(
        initialValue  = if (active) 0.08f else 0f,
        targetValue   = if (active) 0.18f else 0f,
        animationSpec = infiniteRepeatable(
            animation  = tween(1600, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "outer_glow"
    )

    val shieldColor = if (active) ColorAccent else Color(0xFF3A3A4A)

    Box(contentAlignment = Alignment.Center, modifier = Modifier.size(180.dp)) {
        // Outer ambient glow ring
        Box(
            modifier = Modifier
                .size(180.dp)
                .clip(RoundedCornerShape(90.dp))
                .background(
                    Brush.radialGradient(
                        colors = listOf(
                            ColorAccent.copy(alpha = outerGlowAlpha),
                            Color.Transparent
                        )
                    )
                )
        )
        // Inner glow ring
        Box(
            modifier = Modifier
                .size(130.dp)
                .clip(RoundedCornerShape(65.dp))
                .background(
                    Brush.radialGradient(
                        colors = listOf(
                            ColorAccent.copy(alpha = if (active) 0.22f else 0f),
                            Color.Transparent
                        )
                    )
                )
        )
        // Shield circle
        Box(
            contentAlignment = Alignment.Center,
            modifier         = Modifier
                .size(112.dp)
                .scale(scale)
                .clip(RoundedCornerShape(56.dp))
                .background(ColorSurface)
        ) {
            Icon(
                imageVector        = Icons.Filled.Shield,
                contentDescription = "Protection status shield",
                tint               = shieldColor,
                modifier           = Modifier.size(60.dp)
            )
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VPN toggle card
// ─────────────────────────────────────────────────────────────────────────────

@Composable
private fun VpnToggleCard(active: Boolean, onToggle: (Boolean) -> Unit) {
    Surface(
        modifier       = Modifier.fillMaxWidth(),
        shape          = RoundedCornerShape(18.dp),
        color          = ColorSurface,
        tonalElevation = 0.dp
    ) {
        Row(
            modifier              = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 18.dp),
            verticalAlignment     = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column {
                Text(
                    text       = if (active) "Protection Active" else "Protection Off",
                    fontSize   = 16.sp,
                    fontWeight = FontWeight.SemiBold,
                    color      = if (active) ColorStatusActive else ColorTextSecondary
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    text     = if (active)
                        "DNS + HTTPS traffic inspected"
                    else
                        "Enable to start monitoring",
                    fontSize = 12.sp,
                    color    = ColorTextSecondary
                )
            }

            Switch(
                checked         = active,
                onCheckedChange = onToggle,
                colors          = SwitchDefaults.colors(
                    checkedThumbColor    = Color.White,
                    checkedTrackColor    = ColorAccent,
                    uncheckedThumbColor  = ColorTextSecondary,
                    uncheckedTrackColor  = ColorDivider,
                    uncheckedBorderColor = ColorDivider
                )
            )
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Threat counter row — 4 cards: DNS, HTTPS, SMS, Connections
// ─────────────────────────────────────────────────────────────────────────────

@Composable
private fun ThreatCounterRow(counts: ThreatCounts) {
    // Row 1: DNS + HTTPS
    Row(
        modifier              = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        CounterCard("DNS Threats",   counts.dns,                           Modifier.weight(1f), ColorSeverityHigh,    Icons.Filled.Shield)
        CounterCard("HTTPS Scanned", PerfCounters.httpsInspected.get(),   Modifier.weight(1f), ColorAccent,          Icons.Filled.TravelExplore)
    }
    Spacer(Modifier.height(10.dp))
    // Row 2: SMS + Connections
    Row(
        modifier              = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        CounterCard("SMS Scams",    counts.sms,         Modifier.weight(1f), ColorSeverityMedium, Icons.Filled.GppGood)
        CounterCard("Connections",  counts.connections, Modifier.weight(1f), ColorStatusActive)
    }
}

@Composable
private fun CounterCard(label: String, count: Int, modifier: Modifier, accentColor: Color = ColorAccent, icon: ImageVector? = null) {
    Surface(
        modifier = modifier,
        shape    = RoundedCornerShape(16.dp),
        color    = ColorSurface
    ) {
        Column(
            modifier            = Modifier.padding(vertical = 16.dp, horizontal = 12.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            if (icon != null) {
                Icon(
                    imageVector        = icon,
                    contentDescription = label,
                    tint               = accentColor.copy(alpha = 0.7f),
                    modifier           = Modifier.size(18.dp)
                )
                Spacer(Modifier.height(4.dp))
            }
            Text(
                text       = count.toString(),
                fontSize   = 28.sp,
                fontWeight = FontWeight.Bold,
                color      = accentColor
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text      = label,
                fontSize  = 10.sp,
                color     = ColorTextSecondary,
                maxLines  = 1,
                overflow  = TextOverflow.Ellipsis
            )
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Recent threats
// ─────────────────────────────────────────────────────────────────────────────

private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

@Composable
private fun RecentThreatsSection(threats: List<ThreatEvent>) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            text       = "Recent Threats",
            fontSize   = 13.sp,
            fontWeight = FontWeight.SemiBold,
            color      = ColorTextSecondary,
            letterSpacing = 0.8.sp
        )
        Spacer(Modifier.height(10.dp))

        if (threats.isEmpty()) {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape    = RoundedCornerShape(14.dp),
                color    = ColorSurface
            ) {
                Box(
                    modifier          = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 24.dp),
                    contentAlignment  = Alignment.Center
                ) {
                    Text(
                        text     = "No threats detected",
                        fontSize = 13.sp,
                        color    = ColorTextSecondary
                    )
                }
            }
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                threats.forEach { event ->
                    ThreatEventCard(event)
                }
            }
        }
    }
}

@Composable
private fun ThreatEventCard(event: ThreatEvent) {
    val advice = remember(event.type, event.severity) {
        RemediationAdvisor.advise(event.type, event.severity)
    }

    AnimatedVisibility(
        visible  = true,
        enter    = slideInHorizontally(initialOffsetX = { it / 3 }) + fadeIn(tween(250)),
    ) {
        Surface(
            modifier = Modifier.fillMaxWidth(),
            shape    = RoundedCornerShape(14.dp),
            color    = ColorSurface
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 13.dp)
            ) {
                Row(
                    modifier          = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    // Severity bar on the left edge
                    Box(
                        modifier = Modifier
                            .width(3.dp)
                            .height(36.dp)
                            .clip(RoundedCornerShape(2.dp))
                            .background(severityColor(event.severity))
                    )

                    Spacer(Modifier.width(12.dp))

                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text       = event.type.replace('_', ' '),
                            fontSize   = 13.sp,
                            fontWeight = FontWeight.SemiBold,
                            color      = Color.White,
                            maxLines   = 1,
                            overflow   = TextOverflow.Ellipsis
                        )
                        Spacer(Modifier.height(2.dp))
                        Text(
                            text     = event.description,
                            fontSize = 11.sp,
                            color    = ColorTextSecondary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }

                    Spacer(Modifier.width(10.dp))

                    Column(horizontalAlignment = Alignment.End) {
                        SeverityBadge(event.severity)
                        // ML label badge — shown only when classifier returned a non-Benign label
                        if (event.mlLabel.isNotBlank() && event.mlLabel != "Benign") {
                            Spacer(Modifier.height(4.dp))
                            Surface(
                                shape = RoundedCornerShape(4.dp),
                                color = ColorAccent.copy(alpha = 0.12f)
                            ) {
                                Text(
                                    text          = event.mlLabel.uppercase(),
                                    fontSize      = 9.sp,
                                    fontWeight    = FontWeight.Bold,
                                    color         = ColorAccent,
                                    modifier      = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                    letterSpacing = 0.5.sp
                                )
                            }
                        }
                        Spacer(Modifier.height(4.dp))
                        Text(
                            text     = timeFmt.format(Date(event.timestamp)),
                            fontSize = 10.sp,
                            color    = ColorTextSecondary
                        )
                    }
                }

                // ── Remediation chip ──────────────────────────────────────────
                Spacer(Modifier.height(10.dp))
                HorizontalDivider(color = ColorDivider, thickness = 0.5.dp)
                Spacer(Modifier.height(8.dp))
                RemediationChip(advice = advice)
            }
        }
    }
}

@Composable
private fun SeverityBadge(severity: String) {
    val (bg, text) = when (severity) {
        "HIGH"   -> ColorSeverityHigh.copy(alpha = 0.18f)   to ColorSeverityHigh
        "MEDIUM" -> ColorSeverityMedium.copy(alpha = 0.18f) to ColorSeverityMedium
        else     -> ColorSeverityLow.copy(alpha = 0.18f)    to ColorSeverityLow
    }
    Surface(
        shape = RoundedCornerShape(4.dp),
        color = bg
    ) {
        Text(
            text       = severity,
            fontSize   = 9.sp,
            fontWeight = FontWeight.Bold,
            color      = text,
            modifier   = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
            letterSpacing = 0.5.sp
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Keystore status chip
// ─────────────────────────────────────────────────────────────────────────────

@Composable
private fun KeystoreStatusChip(ready: Boolean, info: KeystoreAttestationInfo) {
    val label  = when {
        !ready                               -> "Keystore Initialising"
        info.isStrongBox                     -> "StrongBox Secured"
        info.isTee                           -> "TEE Secured"
        else                                 -> "Software Only"
    }
    val dotColor = when {
        !ready           -> ColorTextSecondary
        info.isTee || info.isStrongBox -> ColorStatusActive
        else             -> ColorSeverityMedium
    }

    Surface(
        shape = RoundedCornerShape(50.dp),
        color = ColorSurface
    ) {
        Row(
            modifier          = Modifier.padding(horizontal = 14.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(7.dp)
                    .clip(RoundedCornerShape(4.dp))
                    .background(dotColor)
            )
            Spacer(Modifier.width(7.dp))
            Text(
                text      = label,
                fontSize  = 11.sp,
                fontWeight = FontWeight.Medium,
                color     = dotColor
            )
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

private fun severityColor(severity: String): Color = when (severity) {
    "HIGH"   -> ColorSeverityHigh
    "MEDIUM" -> ColorSeverityMedium
    else     -> ColorSeverityLow
}

// ─────────────────────────────────────────────────────────────────────────────
// Remediation chip — quick-action recommendation
// ─────────────────────────────────────────────────────────────────────────────

@Composable
private fun RemediationChip(advice: com.sentinelguard.ui.RemediationAdvice) {
    val chipColor = when (advice.urgency) {
        com.sentinelguard.ui.RemediationAdvice.Urgency.CRITICAL -> ColorSeverityHigh
        com.sentinelguard.ui.RemediationAdvice.Urgency.HIGH     -> ColorSeverityMedium
        com.sentinelguard.ui.RemediationAdvice.Urgency.MEDIUM   -> ColorAccent
        com.sentinelguard.ui.RemediationAdvice.Urgency.LOW      -> ColorStatusActive
    }
    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Surface(
                shape = RoundedCornerShape(6.dp),
                color = chipColor.copy(alpha = 0.14f)
            ) {
                Text(
                    text          = "⚡ ${advice.action}",
                    fontSize      = 10.sp,
                    fontWeight    = FontWeight.SemiBold,
                    color         = chipColor,
                    modifier      = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                    letterSpacing = 0.3.sp
                )
            }
        }
        Spacer(Modifier.height(4.dp))
        Text(
            text     = advice.detail,
            fontSize = 10.sp,
            color    = ColorTextSecondary,
            lineHeight = 14.sp
        )
    }
}
