package com.sentinelguard.ui.screens

import androidx.compose.animation.*
import androidx.compose.animation.core.tween
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.BorderStroke
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Verified
import androidx.compose.material3.*
import com.sentinelguard.ml.LlamaExplainerHolder
import com.sentinelguard.ui.RemediationAdvisor
import com.sentinelguard.vpn.ThreatEvent
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material3.pulltorefresh.rememberPullToRefreshState
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sentinelguard.keystore.SignedVerdictEntity
import com.sentinelguard.ui.theme.*
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ThreatLogScreen(
    verdicts:          List<SignedVerdictEntity>,
    onRefresh:         () -> Unit,
    onSaveExplanation: (Long, String) -> Unit = { _, _ -> },
    onExport:          () -> Unit = {},
    exportMessage:     String? = null,
    onExportMsgShown:  () -> Unit = {}
) {
    val pullState    = rememberPullToRefreshState()
    var refreshing   by remember { mutableStateOf(false) }
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(exportMessage) {
        if (!exportMessage.isNullOrBlank()) {
            snackbarHostState.showSnackbar(exportMessage)
            onExportMsgShown()
        }
    }

    Scaffold(
        containerColor = ColorBackground,
        snackbarHost   = { SnackbarHost(snackbarHostState) }
    ) { innerPadding ->
    PullToRefreshBox(
        isRefreshing = refreshing,
        onRefresh    = {
            refreshing = true
            onRefresh()
            refreshing = false
        },
        state        = pullState,
        modifier     = Modifier
            .fillMaxSize()
            .background(ColorBackground)
            .padding(innerPadding)
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
        ) {
            // ── Screen header ─────────────────────────────────────────────────
            ScreenHeader(
                title    = "Threat Log",
                subtitle = "${verdicts.size} signed record${if (verdicts.size != 1) "s" else ""}"
            )

            // ── Export button ─────────────────────────────────────────────────
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 20.dp, vertical = 4.dp),
                horizontalArrangement = Arrangement.End
            ) {
                OutlinedButton(
                    onClick = onExport,
                    border  = BorderStroke(1.dp, ColorAccent),
                    shape   = RoundedCornerShape(10.dp)
                ) {
                    Text("Export Audit Log", color = ColorAccent, fontSize = 12.sp)
                }
            }

            // ── List / empty state ────────────────────────────────────────────
            if (verdicts.isEmpty()) {
                EmptyLogState()
            } else {
                LazyColumn(
                    modifier          = Modifier.fillMaxSize(),
                    contentPadding    = PaddingValues(horizontal = 20.dp, vertical = 12.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    items(
                        items = verdicts,
                        key   = { it.id }
                    ) { entity ->
                        VerdictRow(entity, onSaveExplanation = onSaveExplanation)
                    }
                    item { Spacer(Modifier.height(16.dp)) }
                }
            }
        }
    }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Empty state
// ─────────────────────────────────────────────────────────────────────────────

@Composable
private fun EmptyLogState() {
    Box(
        modifier         = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Box(
                contentAlignment = Alignment.Center,
                modifier         = Modifier
                    .size(90.dp)
                    .clip(RoundedCornerShape(45.dp))
                    .background(ColorSurface)
            ) {
                Icon(
                    imageVector        = Icons.Filled.Shield,
                    contentDescription = null,
                    tint               = ColorAccent.copy(alpha = 0.5f),
                    modifier           = Modifier.size(44.dp)
                )
            }
            Spacer(Modifier.height(18.dp))
            Text(
                text       = "No threats detected yet",
                fontSize   = 15.sp,
                fontWeight = FontWeight.Medium,
                color      = Color.White
            )
            Spacer(Modifier.height(6.dp))
            Text(
                text     = "Signed verdicts will appear here\nas threats are identified.",
                fontSize = 12.sp,
                color    = ColorTextSecondary,
                textAlign = androidx.compose.ui.text.style.TextAlign.Center
            )
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Verdict row — expandable
// ─────────────────────────────────────────────────────────────────────────────

private val logDateFmt = SimpleDateFormat("MMM dd  HH:mm:ss", Locale.getDefault())

@Composable
private fun VerdictRow(
    entity:            SignedVerdictEntity,
    onSaveExplanation: (Long, String) -> Unit = { _, _ -> }
) {
    var expanded by remember { mutableStateOf(false) }

    Surface(
        modifier  = Modifier.fillMaxWidth(),
        shape     = RoundedCornerShape(16.dp),
        color     = ColorSurface,
        onClick   = { expanded = !expanded }
    ) {
        Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 14.dp)) {

            // ── Collapsed header row ──────────────────────────────────────────
            Row(
                modifier          = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Severity bar
                Box(
                    modifier = Modifier
                        .width(3.dp)
                        .height(40.dp)
                        .clip(RoundedCornerShape(2.dp))
                        .background(severityColor(entity.severity))
                )

                Spacer(Modifier.width(12.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text       = entity.threatType.replace('_', ' '),
                        fontSize   = 13.sp,
                        fontWeight = FontWeight.SemiBold,
                        color      = Color.White,
                        maxLines   = 1,
                        overflow   = TextOverflow.Ellipsis
                    )
                    Spacer(Modifier.height(3.dp))
                    Text(
                        text     = logDateFmt.format(Date(entity.timestamp)),
                        fontSize = 11.sp,
                        color    = ColorTextSecondary
                    )
                }

                Spacer(Modifier.width(10.dp))

                Column(horizontalAlignment = Alignment.End) {
                    SeverityBadge(entity.severity)
                    if (entity.confidence > 0f) {
                        Spacer(Modifier.height(6.dp))
                        ConfidenceBar(entity.confidence)
                    }
                }
            }

            // ── Expanded details ──────────────────────────────────────────────
            AnimatedVisibility(
                visible      = expanded,
                enter        = expandVertically(tween(200)) + fadeIn(tween(200)),
                exit         = shrinkVertically(tween(180)) + fadeOut(tween(150))
            ) {
                Column {
                    Spacer(Modifier.height(14.dp))
                    HorizontalDivider(color = ColorDivider, thickness = 1.dp)
                    Spacer(Modifier.height(12.dp))

                    // Hardware verification chip
                    HardwareVerifiedChip()

                    Spacer(Modifier.height(12.dp))

                    // ── Detected content ──────────────────────────────────────
                    if (entity.content.isNotBlank()) {
                        DetailLabel("DETECTED CONTENT")
                        Spacer(Modifier.height(4.dp))
                        Surface(
                            shape = RoundedCornerShape(8.dp),
                            color = ColorSurfaceVariant
                        ) {
                            Text(
                                text       = entity.content,
                                fontSize   = 12.sp,
                                fontFamily = FontFamily.Monospace,
                                color      = Color.White,
                                lineHeight = 18.sp,
                                modifier   = Modifier.padding(horizontal = 10.dp, vertical = 8.dp)
                            )
                        }
                        Spacer(Modifier.height(10.dp))
                    }

                    // ── ML label ──────────────────────────────────────────────
                    if (entity.mlLabel.isNotBlank()) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            DetailLabel("ML CLASSIFICATION")
                            Spacer(Modifier.width(8.dp))
                            Surface(
                                shape = RoundedCornerShape(4.dp),
                                color = ColorAccent.copy(alpha = 0.15f)
                            ) {
                                Text(
                                    text          = entity.mlLabel,
                                    fontSize      = 10.sp,
                                    fontWeight    = FontWeight.Bold,
                                    color         = ColorAccent,
                                    modifier      = Modifier.padding(horizontal = 7.dp, vertical = 3.dp),
                                    letterSpacing = 0.3.sp
                                )
                            }
                        }
                        Spacer(Modifier.height(10.dp))
                    }

                    // ── Remediation recommendation ────────────────────────────
                    val advice = remember(entity.threatType, entity.severity) {
                        RemediationAdvisor.advise(entity.threatType, entity.severity)
                    }
                    val urgencyColor = when (advice.urgency) {
                        com.sentinelguard.ui.RemediationAdvice.Urgency.CRITICAL -> ColorSeverityHigh
                        com.sentinelguard.ui.RemediationAdvice.Urgency.HIGH     -> ColorSeverityMedium
                        com.sentinelguard.ui.RemediationAdvice.Urgency.MEDIUM   -> ColorAccent
                        com.sentinelguard.ui.RemediationAdvice.Urgency.LOW      -> ColorStatusActive
                    }
                    Surface(
                        shape = androidx.compose.foundation.shape.RoundedCornerShape(10.dp),
                        color = urgencyColor.copy(alpha = 0.08f)
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 12.dp, vertical = 10.dp)
                        ) {
                            Text(
                                text          = "RECOMMENDED ACTION",
                                fontSize      = 9.sp,
                                fontWeight    = androidx.compose.ui.text.font.FontWeight.Bold,
                                color         = urgencyColor,
                                letterSpacing = 0.8.sp
                            )
                            Spacer(Modifier.height(4.dp))
                            Text(
                                text       = advice.action,
                                fontSize   = 13.sp,
                                fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold,
                                color      = Color.White
                            )
                            Spacer(Modifier.height(3.dp))
                            Text(
                                text       = advice.detail,
                                fontSize   = 11.sp,
                                color      = ColorTextSecondary,
                                lineHeight = 16.sp
                            )
                        }
                    }

                    Spacer(Modifier.height(10.dp))

                    // Signature preview
                    DetailLabel("Signature (SHA256withECDSA)")
                    Spacer(Modifier.height(4.dp))
                    SignaturePreview(entity.signatureHex)

                    Spacer(Modifier.height(8.dp))

                    // Public key preview
                    DetailLabel("Public Key (X.509)")
                    Spacer(Modifier.height(4.dp))
                    SignaturePreview(entity.publicKeyHex)

                    // ── AI Explanation ────────────────────────────────────────
                    Spacer(Modifier.height(12.dp))
                    HorizontalDivider(color = ColorDivider, thickness = 1.dp)
                    Spacer(Modifier.height(12.dp))

                    // Show saved explanation if already generated
                    if (entity.explanation.isNotBlank()) {
                        DetailLabel("AI Explanation")
                        Spacer(Modifier.height(6.dp))
                        Text(
                            text       = entity.explanation,
                            fontSize   = 13.sp,
                            color      = Color.White,
                            lineHeight = 20.sp
                        )
                        Spacer(Modifier.height(8.dp))
                    }

                    // "Explain with AI" button — only when Llama available and no prior explanation
                    val llamaAvail = LlamaExplainerHolder.explainer?.isAvailable == true
                    if (entity.explanation.isBlank() && llamaAvail) {
                        var showSheet by remember { mutableStateOf(false) }

                        OutlinedButton(
                            onClick  = { showSheet = true },
                            border   = BorderStroke(1.dp, ColorAccent),
                            modifier = Modifier.fillMaxWidth(),
                            shape    = RoundedCornerShape(10.dp)
                        ) {
                            Icon(
                                imageVector        = Icons.Filled.AutoAwesome,
                                contentDescription = null,
                                tint               = ColorAccent,
                                modifier           = Modifier.size(16.dp)
                            )
                            Spacer(Modifier.width(8.dp))
                            Text("Explain with AI", color = ColorAccent, fontSize = 13.sp)
                        }

                        if (showSheet) {
                            val threatEvent = ThreatEvent(
                                type        = entity.threatType,
                                severity    = entity.severity,
                                // Use actual detected content so Llama gets meaningful context,
                                // not a stub string. Falls back to threatType if content is blank.
                                description = entity.content.ifBlank { entity.threatType },
                                timestamp   = entity.timestamp,
                                mlLabel     = entity.mlLabel
                            )
                            ExplanationBottomSheet(
                                event     = threatEvent,
                                verdictId = entity.id,
                                onDismiss = { showSheet = false },
                                onSaved   = { id, text ->
                                    onSaveExplanation(id, text)
                                    showSheet = false
                                }
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun HardwareVerifiedChip() {
    Surface(
        shape = RoundedCornerShape(50.dp),
        color = ColorStatusActive.copy(alpha = 0.12f)
    ) {
        Row(
            modifier          = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector        = Icons.Filled.Verified,
                contentDescription = null,
                tint               = ColorStatusActive,
                modifier           = Modifier.size(13.dp)
            )
            Spacer(Modifier.width(5.dp))
            Text(
                text       = "Hardware Verified",
                fontSize   = 11.sp,
                fontWeight = FontWeight.SemiBold,
                color      = ColorStatusActive,
                letterSpacing = 0.3.sp
            )
        }
    }
}

@Composable
private fun SignaturePreview(hex: String) {
    val preview = if (hex.length > 32) hex.take(32) + "…" else hex
    Surface(
        shape = RoundedCornerShape(8.dp),
        color = ColorSurfaceVariant
    ) {
        Text(
            text       = preview,
            fontSize   = 10.sp,
            fontFamily = FontFamily.Monospace,
            color      = ColorTextSecondary,
            modifier   = Modifier.padding(horizontal = 10.dp, vertical = 7.dp)
        )
    }
}

@Composable
private fun DetailLabel(text: String) {
    Text(
        text          = text,
        fontSize      = 10.sp,
        color         = ColorTextSecondary,
        letterSpacing = 0.5.sp,
        fontWeight    = FontWeight.Medium
    )
}

@Composable
private fun ConfidenceBar(confidence: Float) {
    val pct = (confidence * 100).toInt()
    val barColor = when {
        confidence >= 0.75f -> ColorSeverityHigh
        confidence >= 0.45f -> ColorSeverityMedium
        else                -> ColorStatusActive
    }
    Column(horizontalAlignment = Alignment.End) {
        Text(
            text     = "$pct%",
            fontSize = 10.sp,
            color    = barColor,
            fontWeight = FontWeight.SemiBold
        )
        Spacer(Modifier.height(3.dp))
        Box(
            modifier = Modifier
                .width(48.dp)
                .height(3.dp)
                .clip(RoundedCornerShape(2.dp))
                .background(ColorDivider)
        ) {
            Box(
                modifier = Modifier
                    .fillMaxHeight()
                    .fillMaxWidth(confidence.coerceIn(0f, 1f))
                    .background(barColor)
            )
        }
    }
}

@Composable
private fun SeverityBadge(severity: String) {
    val (bg, fg) = when (severity) {
        "HIGH"   -> ColorSeverityHigh.copy(alpha = 0.18f)   to ColorSeverityHigh
        "MEDIUM" -> ColorSeverityMedium.copy(alpha = 0.18f) to ColorSeverityMedium
        else     -> ColorSeverityLow.copy(alpha = 0.18f)    to ColorSeverityLow
    }
    Surface(shape = RoundedCornerShape(4.dp), color = bg) {
        Text(
            text          = severity,
            fontSize      = 9.sp,
            fontWeight    = FontWeight.Bold,
            color         = fg,
            modifier      = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
            letterSpacing = 0.5.sp
        )
    }
}

private fun severityColor(s: String): Color = when (s) {
    "HIGH"   -> ColorSeverityHigh
    "MEDIUM" -> ColorSeverityMedium
    else     -> ColorSeverityLow
}
