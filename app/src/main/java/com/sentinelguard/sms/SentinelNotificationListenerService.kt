package com.sentinelguard.sms

import android.app.Notification
import android.os.Bundle
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import com.sentinelguard.BuildConfig
import com.sentinelguard.vpn.ConnectionAnalyser

/**
 * SentinelNotificationListenerService — monitors notifications from selected
 * messaging applications and passes their text content through [ScamDetector].
 *
 * Monitored packages:
 *   - com.whatsapp
 *   - com.google.android.apps.messaging  (Google Messages / RCS)
 *   - com.truecaller
 *   - org.telegram.messenger
 *   - com.instagram.android
 *
 * When a scam is detected the service:
 *   1. Injects a [com.sentinelguard.vpn.ThreatEvent] via [ConnectionAnalyserHolder].
 *   2. Posts a local alert notification via [SmsReceiver.postAlertNotification].
 *
 * Notifications originating from SentinelGuard's own package are silently
 * skipped to prevent feedback loops (our own alert firing the detector again).
 *
 * This service must be granted Notification Access by the user in
 * Settings → Apps → Special app access → Notification access.
 */
class SentinelNotificationListenerService : NotificationListenerService() {

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        val pkg = sbn.packageName ?: return

        // ── Guard: skip our own notifications ─────────────────────────────────
        if (pkg == OWN_PACKAGE) return

        // ── Guard: only process monitored messaging apps ───────────────────────
        if (pkg !in MONITORED_PACKAGES) return

        val extras: Bundle = sbn.notification?.extras ?: return

        // Prefer BigText (expanded) over collapsed text — richer content
        val bigText = extras.getCharSequence(Notification.EXTRA_BIG_TEXT)?.toString()
        val text    = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString()
        val body    = bigText?.takeIf { it.isNotBlank() } ?: text?.takeIf { it.isNotBlank() }

        if (body == null) return

        val detector = ScamDetectorHolder.detector
        if (detector == null) {
            Log.w(TAG, "ScamDetector not initialised — skipping notification from $pkg")
            return
        }

        SmsReceiver.ensureAlertChannel(applicationContext)

        Log.d(TAG, "Analysing notification from $pkg (${body.length} chars)")

        val result = detector.analyse(body)
        if (!result.isScam) return

        Log.w(TAG, "Scam detected in notification from $pkg [${result.category}] " +
                "confidence=%.0f%%".format(result.confidence * 100))

        // ── 1. Inject into unified threat stream ──────────────────────────────
        val mlLabel = result.matchedSignals
            .firstOrNull { it.startsWith("ML_") }
            ?.removePrefix("ML_")
            ?.lowercase()
            ?.replaceFirstChar { it.uppercase() }
            ?: ""

        ConnectionAnalyserHolder.analyser?.injectThreatEvent(
            com.sentinelguard.vpn.ThreatEvent(
                type        = "SMS_SCAM",
                severity    = SmsReceiver.severityFor(result.confidence),
                description = "[${result.category}] Suspicious notification from $pkg. " +
                              "Confidence: %.0f%%. Signals: ${result.matchedSignals.joinToString()}"
                              .format(result.confidence * 100),
                timestamp   = result.timestamp,
                mlLabel     = mlLabel,
                mlScore     = result.confidence
            )
        )

        // ── 2. Post local alert notification ─────────────────────────────────
        val appLabel = runCatching {
            packageManager.getApplicationLabel(
                packageManager.getApplicationInfo(pkg, 0)
            ).toString()
        }.getOrElse { pkg }

        SmsReceiver.postAlertNotification(
            context = applicationContext,
            result  = result,
            source  = appLabel
        )
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification) {
        // No action needed — we analyse on post, not on removal.
    }

    companion object {
        private const val TAG = "SentinelNotifListener"

        /**
         * This app's own package name — guards against feedback loops where
         * SentinelGuard's own alert notifications re-trigger the listener.
         *
         * Uses [BuildConfig.APPLICATION_ID] so debug builds (which have an
         * `.debug` applicationIdSuffix) are also correctly filtered.
         */
        private val OWN_PACKAGE = BuildConfig.APPLICATION_ID

        /** Package names of messaging apps whose notifications are inspected. */
        private val MONITORED_PACKAGES = setOf(
            "com.whatsapp",
            "com.google.android.apps.messaging",
            "com.truecaller",
            "org.telegram.messenger",
            "com.instagram.android"
        )
    }
}
