package com.sentinelguard.keystore

import android.content.Context
import android.util.Log
import com.sentinelguard.dns.SentinelDatabase
import com.sentinelguard.sms.ConnectionAnalyserHolder
import com.sentinelguard.vpn.ConnectionAnalyser
import com.sentinelguard.vpn.ThreatEvent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * VerdictLogger — subscribes to the unified [com.sentinelguard.vpn.ConnectionAnalyser.threatEvents]
 * SharedFlow and produces a hardware-signed, Room-persisted audit record for
 * every [ThreatEvent] detected during a session.
 *
 * Pipeline per event:
 *   ThreatEvent
 *     → [VerdictPayload] (domain/IP extracted from description heuristically)
 *     → [SentinelKeyManager.signVerdict] → [SignedVerdict]
 *     → [SignedVerdictDao.insert] → Room `signed_verdicts` table
 *
 * Started once from [com.sentinelguard.SentinelApplication.startVerdictLogger].
 * Uses its own [CoroutineScope] with [SupervisorJob] so a signing or DB error
 * on one event does not kill the collector for subsequent events.
 *
 * Thread model: all work runs on [Dispatchers.IO] — signing calls into
 * Android Keystore (may do IPC to `keystore2` daemon) and Room is I/O-bound.
 */
object VerdictLogger {

    private const val TAG = "VerdictLogger"

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /**
     * Begin collecting threat events and logging signed verdicts.
     *
     * [context] is used to open the Room database. The [ConnectionAnalyserHolder]
     * must already have an [com.sentinelguard.vpn.ConnectionAnalyser] registered
     * before this is called; otherwise the method is a no-op with a warning.
     *
     * Safe to call multiple times — the SharedFlow collector is launched as a
     * coroutine child and deduplicated by [scope]'s [SupervisorJob].
     */
    fun start(context: Context) {
        val analyser = ConnectionAnalyserHolder.analyser
        if (analyser == null) {
            Log.w(TAG, "ConnectionAnalyser not ready — VerdictLogger not started")
            return
        }

        val dao = SentinelDatabase.getInstance(context).signedVerdictDao()

        scope.launch {
            Log.i(TAG, "VerdictLogger collecting threat events")

            analyser.threatEvents.collect { event ->
                try {
                    processEvent(event, dao)
                } catch (e: Exception) {
                    // Log and continue — SupervisorJob ensures one failure doesn't
                    // cancel all future event processing
                    Log.e(TAG, "Failed to log verdict for ${event.type}", e)
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Per-event processing
    // -------------------------------------------------------------------------

    private suspend fun processEvent(event: ThreatEvent, dao: SignedVerdictDao) {
        if (!SentinelKeyManagerHolder.isReady) {
            Log.w(TAG, "Keystore not ready — skipping verdict for ${event.type}")
            return
        }

        // Build the payload — extract optional domain/IP from description text
        val payload = VerdictPayload(
            threatType  = event.type,
            severity    = event.severity,
            domain      = extractDomain(event.description),
            sourceIp    = extractIp(event.description),
            confidence  = extractConfidence(event.description),
            timestamp   = event.timestamp
        )

        // Sign synchronously on Dispatchers.IO (Keystore IPC is I/O-bound)
        val signed = SentinelKeyManager.signVerdict(payload)

        // Persist to Room
        val entity = SignedVerdictEntity(
            threatType   = payload.threatType,
            severity     = payload.severity,
            confidence   = payload.confidence,
            timestamp    = payload.timestamp,
            signatureHex = signed.signature.toHex(),
            publicKeyHex = signed.publicKeyEncoded.toHex(),
            content      = event.description.take(300),
            mlLabel      = event.mlLabel
        )

        val rowId = dao.insert(entity)
        Log.d(TAG, "Verdict persisted: id=$rowId type=${event.type} [${event.severity}]")
    }

    // -------------------------------------------------------------------------
    // Extraction helpers
    // ─────────────────────────────────────────────────────────────────────────
    // These parse structured substrings from ThreatEvent.description without
    // requiring a formal schema. If the format changes, only these helpers need
    // updating — the signing pipeline is unaffected.

    /**
     * Heuristically extract a domain name from [text].
     * Looks for patterns like "host: foo.com", "domain: foo.com", or the first
     * token that looks like an FQDN (contains a dot, no slashes, no colons).
     */
    private fun extractDomain(text: String): String? {
        DOMAIN_LABEL_REGEX.find(text)?.groupValues?.getOrNull(1)?.let { return it }
        return FQDN_REGEX.find(text)?.value
    }

    /**
     * Heuristically extract an IPv4 address from [text].
     * Looks for patterns like "ip: 1.2.3.4" or a bare dotted-decimal address.
     */
    private fun extractIp(text: String): String? {
        IP_LABEL_REGEX.find(text)?.groupValues?.getOrNull(1)?.let { return it }
        return IPV4_REGEX.find(text)?.value
    }

    /**
     * Extract a confidence percentage from [text] if present (e.g. "Confidence: 78%").
     * Returns 0.0 for event types (network/VPN) that don't carry a confidence score.
     */
    private fun extractConfidence(text: String): Float {
        return CONFIDENCE_REGEX.find(text)?.groupValues?.getOrNull(1)
            ?.toFloatOrNull()
            ?.div(100f)
            ?: 0.0f
    }

    // -------------------------------------------------------------------------
    // Regex constants
    // -------------------------------------------------------------------------

    private val DOMAIN_LABEL_REGEX = Regex(
        """(?:host|domain|hostname):\s*([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})""",
        RegexOption.IGNORE_CASE
    )
    private val FQDN_REGEX = Regex(
        """(?<![/\w])([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+\.[a-zA-Z]{2,})"""
    )
    private val IP_LABEL_REGEX = Regex(
        """(?:ip|address):\s*(\d{1,3}(?:\.\d{1,3}){3})""",
        RegexOption.IGNORE_CASE
    )
    private val IPV4_REGEX = Regex(
        """\b(\d{1,3}(?:\.\d{1,3}){3})\b"""
    )
    private val CONFIDENCE_REGEX = Regex(
        """[Cc]onfidence:\s*(\d{1,3})%"""
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// ByteArray → lowercase hex string (file-private)
// ─────────────────────────────────────────────────────────────────────────────

private fun ByteArray.toHex(): String =
    joinToString("") { "%02x".format(it) }
