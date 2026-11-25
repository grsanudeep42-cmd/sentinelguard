package com.sentinelguard.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AutoAwesome
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sentinelguard.ml.LlamaExplainerHolder
import com.sentinelguard.ui.theme.*
import com.sentinelguard.vpn.ThreatEvent

// ─────────────────────────────────────────────────────────────────────────────
// ExplanationBottomSheet
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Modal bottom sheet that streams a Llama 3.2 1B plain-English explanation for
 * a [ThreatEvent]. Tokens are appended one-by-one as the model generates them,
 * giving the user live streaming output.
 *
 * When generation finishes [onSaved] is called with the full text so the
 * caller can persist it via [com.sentinelguard.ui.MainViewModel.saveExplanation].
 *
 * If the model files are absent ([LlamaExplainerHolder.explainer?.isAvailable]
 * returns false) the explainer returns a friendly fallback message.
 *
 * @param event     The threat event to explain.
 * @param verdictId The Room row ID of the signed verdict (for persistence).
 * @param onDismiss Called when the user closes the sheet or generation finishes.
 * @param onSaved   Called with `(verdictId, fullExplanationText)` once the
 *                  model finishes so the caller can persist the result.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExplanationBottomSheet(
    event:     ThreatEvent,
    verdictId: Long,
    onDismiss: () -> Unit,
    onSaved:   (Long, String) -> Unit
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    var tokens     by remember { mutableStateOf("") }
    var done       by remember { mutableStateOf(false) }

    // Start generation as soon as the sheet is composed.
    LaunchedEffect(verdictId) {
        LlamaExplainerHolder.explainer?.explain(event) { token ->
            tokens += token
        }
        done = true
        if (tokens.isNotBlank()) {
            onSaved(verdictId, tokens)
        }
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState       = sheetState,
        containerColor   = ColorSurface,
        shape            = RoundedCornerShape(topStart = 20.dp, topEnd = 20.dp)
    ) {
        Column(
            modifier = Modifier
                .padding(horizontal = 24.dp)
                .padding(top = 4.dp, bottom = 32.dp)
                .navigationBarsPadding()
        ) {
            // ── Header ────────────────────────────────────────────────────────
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector        = Icons.Filled.AutoAwesome,
                    contentDescription = null,
                    tint               = ColorAccent,
                    modifier           = Modifier.size(20.dp)
                )
                Spacer(Modifier.width(10.dp))
                Column {
                    Text(
                        text       = "AI Explanation",
                        fontWeight = FontWeight.SemiBold,
                        fontSize   = 16.sp,
                        color      = Color.White
                    )
                    Text(
                        text     = "Powered by Llama 3.2 1B — on-device via ExecuTorch",
                        fontSize = 11.sp,
                        color    = ColorTextSecondary
                    )
                }
            }

            HorizontalDivider(
                modifier  = Modifier.padding(vertical = 16.dp),
                color     = ColorDivider,
                thickness = 1.dp
            )

            // ── Content ───────────────────────────────────────────────────────
            if (tokens.isBlank() && !done) {
                // Loading state
                Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(
                        modifier    = Modifier.size(16.dp),
                        color       = ColorAccent,
                        strokeWidth = 2.dp
                    )
                    Spacer(Modifier.width(10.dp))
                    Text(
                        text     = "Generating explanation…",
                        color    = ColorTextSecondary,
                        fontSize = 13.sp
                    )
                }
            } else {
                // Streamed / final text
                Text(
                    text       = tokens.ifBlank { "No explanation generated." },
                    color      = Color.White,
                    fontSize   = 14.sp,
                    lineHeight = 22.sp
                )
            }

            // ── Close button (shown after generation finishes) ────────────────
            if (done) {
                Spacer(Modifier.height(24.dp))
                Button(
                    onClick  = onDismiss,
                    modifier = Modifier.fillMaxWidth(),
                    colors   = ButtonDefaults.buttonColors(containerColor = ColorAccent),
                    shape    = RoundedCornerShape(12.dp)
                ) {
                    Text("Close", fontWeight = FontWeight.Medium)
                }
            }
        }
    }
}
