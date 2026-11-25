package com.sentinelguard.sms

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import androidx.core.app.NotificationCompat
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Telephony
import android.util.Log
import com.sentinelguard.ui.screens.PerfCounters
import com.sentinelguard.vpn.ConnectionAnalyser
import com.sentinelguard.vpn.ThreatEvent

/**
 * SmsReceiver — intercepts incoming SMS messages and routes them through
 * [ScamDetector] to detect phishing, smishing, OTP-fraud, and bank-scam content.
 *
 * On a positive detection it:
 *  1. Calls [ConnectionAnalyser.injectThreatEvent] so the unified threat stream
 *     (observed by the VPN layer and UI) records the event.
 *  2. Posts a high-priority local alert notification on [CHANNEL_ALERTS].
 *
 * Note: BroadcastReceivers run on the main thread with a strict 10-second
 * time limit (Android). [ScamDetector.analyse] is fully synchronous and
 * regex-based so it comfortably fits within that window.
 */
class SmsReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        val detector = ScamDetectorHolder.detector
        if (detector == null) {
            Log.w(TAG, "ScamDetector not initialised — dropping SMS analysis")
            return
        }

        ensureAlertChannel(context)

        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        if (messages.isNullOrEmpty()) return

        // Stitch multi-part SMS back into a single body before analysis
        val sender   = messages.firstOrNull()?.originatingAddress ?: "unknown"
        val fullBody = messages.joinToString(separator = "") { it.messageBody ?: "" }

        if (fullBody.isBlank()) return

        Log.d(TAG, "Analysing SMS from $sender (${fullBody.length} chars)")

        PerfCounters.smsScanned.incrementAndGet()
        val result = detector.analyse(fullBody)

        if (!result.isScam) return

        Log.w(TAG, "SMS scam detected from $sender [${result.category}] " +
                "confidence=%.0f%%".format(result.confidence * 100))

        // ── 1. Inject threat event into the unified stream ────────────────────
        // Extract ml label from matched signals (added by ScamDetector when ML fires)
        val mlLabel = result.matchedSignals
            .firstOrNull { it.startsWith("ML_") }
            ?.removePrefix("ML_")
            ?.lowercase()
            ?.replaceFirstChar { it.uppercase() }
            ?: ""

        ConnectionAnalyserHolder.analyser?.injectThreatEvent(
            ThreatEvent(
                type        = "SMS_SCAM",
                severity    = severityFor(result.confidence),
                description = "[${result.category}] Suspicious SMS from $sender. " +
                              "Confidence: %.0f%%. Signals: ${result.matchedSignals.joinToString()}"
                              .format(result.confidence * 100),
                timestamp   = result.timestamp,
                mlLabel     = mlLabel,
                mlScore     = result.confidence
            )
        )

        // ── 2. Post local alert notification ──────────────────────────────────
        postAlertNotification(context, result, source = "SMS from $sender")
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    companion object {
        private const val TAG = "SmsReceiver"

        internal const val CHANNEL_ALERTS = "sentinel_alerts"
        private const val CHANNEL_ALERTS_NAME = "Threat Alerts"
        private const val CHANNEL_ALERTS_DESC =
            "High-priority alerts when SentinelGuard detects a scam or threat"

        /** Map confidence score to severity label. */
        internal fun severityFor(confidence: Float): String = when {
            confidence >= 0.75f -> "HIGH"
            else                -> "MEDIUM"
        }

        /** Ensure the alert notification channel exists (idempotent, API ≥ 26). */
        internal fun ensureAlertChannel(context: Context) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
            val nm = context.getSystemService(NotificationManager::class.java)
            if (nm.getNotificationChannel(CHANNEL_ALERTS) != null) return

            val channel = NotificationChannel(
                CHANNEL_ALERTS,
                CHANNEL_ALERTS_NAME,
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = CHANNEL_ALERTS_DESC
                enableVibration(true)
                setShowBadge(true)
            }
            nm.createNotificationChannel(channel)
        }

        /** Post a user-visible alert notification for a confirmed scam result. */
        internal fun postAlertNotification(
            context:  Context,
            result:   ScamResult,
            source:   String
        ) {
            val nm = context.getSystemService(NotificationManager::class.java)

            // Open the app when the user taps the notification
            val tapIntent = context.packageManager
                .getLaunchIntentForPackage(context.packageName)
                ?.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
                ?: Intent()
            val pendingIntent = PendingIntent.getActivity(
                context,
                0,
                tapIntent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )

            val confidencePct = "%.0f".format(result.confidence * 100)
            val title = "⚠ Scam Detected — ${result.category.replace('_', ' ')}"
            val body  = "From: $source · Confidence: $confidencePct%"

            // NotificationCompat handles both old and new API without deprecation
            val notification = NotificationCompat.Builder(context, CHANNEL_ALERTS)
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle(title)
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(
                    "$body\nSignals: ${result.matchedSignals.joinToString()}"
                ))
                .setContentIntent(pendingIntent)
                .setAutoCancel(true)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .build()

            // Use a stable ID derived from timestamp to avoid overwriting rapid alerts
            val notifId = (result.timestamp % Int.MAX_VALUE).toInt()
            nm.notify(notifId, notification)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConnectionAnalyserHolder — mirrors DnsInspectorHolder pattern
// Set by SentinelApplication so BroadcastReceivers can reach the analyser
// without a Service reference.
// ─────────────────────────────────────────────────────────────────────────────

object ConnectionAnalyserHolder {
    @Volatile
    var analyser: ConnectionAnalyser? = null
}
