package com.sentinelguard.vpn

import android.util.Log
import com.sentinelguard.ml.ThreatClassifierHolder
import com.sentinelguard.ml.ThreatLabel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow

// ─────────────────────────────────────────────────────────────────────────────
// Domain model
// ─────────────────────────────────────────────────────────────────────────────

/**
 * A detected network-level threat event emitted by [ConnectionAnalyser].
 *
 * @param type        Short machine-readable label (e.g. "MALWARE_PORT", "BEACON").
 * @param severity    One of: "LOW", "MEDIUM", "HIGH".
 * @param description Human-readable explanation for display / logging.
 * @param timestamp   Epoch-millisecond of detection.
 * @param mlLabel     [com.sentinelguard.ml.ThreatLabel] name assigned by the on-device
 *                    MobileBERT classifier. Empty string when classifier is unavailable
 *                    or returned [com.sentinelguard.ml.ThreatLabel.Benign].
 * @param mlScore     Classifier confidence in [0.0, 1.0]. 0.0 when classifier is not run.
 */
data class ThreatEvent(
    val type:        String,
    val severity:    String,
    val description: String,
    val timestamp:   Long,
    // ML enrichment — optional, populated by ThreatClassifier post-detection.
    // Both fields have defaults so all existing construction sites compile unchanged.
    val mlLabel: String = "",
    val mlScore: Float  = 0f
)

// ─────────────────────────────────────────────────────────────────────────────
// ConnectionAnalyser
// ─────────────────────────────────────────────────────────────────────────────

/**
 * ConnectionAnalyser — stateful, in-memory analysis of live packet metadata.
 *
 * Rules applied to every [PacketMeta]:
 *
 * 1. **Known malware port** — destination port in [MALWARE_PORTS] → HIGH threat.
 * 2. **Beacon detection** — same destination IP contacted > [BEACON_THRESHOLD]
 *    times within [BEACON_WINDOW_MS] → MEDIUM threat (possible C2 beaconing).
 *
 * Recent connection state is maintained in a [LinkedHashMap] capped at
 * [MAX_ENTRIES] to bound memory use. The oldest entry is evicted when full.
 *
 * Results are published on [threatEvents] as a hot [SharedFlow] with a replay
 * buffer of [FLOW_REPLAY] so late collectors receive the most recent events.
 */
class ConnectionAnalyser {

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    private val _threatEvents = MutableSharedFlow<ThreatEvent>(
        replay        = FLOW_REPLAY,
        extraBufferCapacity = 64
    )

    /** Hot [SharedFlow] of detected [ThreatEvent]s. Collect from a coroutine. */
    val threatEvents: SharedFlow<ThreatEvent> = _threatEvents.asSharedFlow()

    // -------------------------------------------------------------------------
    // Internal state
    // -------------------------------------------------------------------------

    /**
     * Key   : destination IP address.
     * Value : list of epoch-millisecond timestamps for recent connections.
     *
     * Capped at [MAX_ENTRIES] using eldest-removal policy.
     */
    private val recentConnections: LinkedHashMap<String, ArrayDeque<Long>> =
        object : LinkedHashMap<String, ArrayDeque<Long>>(MAX_ENTRIES, 0.75f, true) {
            override fun removeEldestEntry(
                eldest: MutableMap.MutableEntry<String, ArrayDeque<Long>>
            ): Boolean = size > MAX_ENTRIES
        }

    // -------------------------------------------------------------------------
    // Analysis entry point
    // -------------------------------------------------------------------------

    /**
     * Analyse [meta] synchronously (called from the VPN packet-read coroutine).
     * Any [ThreatEvent]s detected are emitted on [threatEvents] without blocking.
     */
    fun analyse(meta: PacketMeta) {
        checkMalwarePort(meta)
        trackAndCheckBeacon(meta)
    }

    /**
     * Accept a [ThreatEvent] produced by an external subsystem (e.g. [DnsInspector])
     * and publish it on [threatEvents] so all collectors see a unified event stream.
     */
    fun injectThreatEvent(event: ThreatEvent) = emit(event)

    // -------------------------------------------------------------------------
    // Rule 1 — known malware port
    // -------------------------------------------------------------------------

    private fun checkMalwarePort(meta: PacketMeta) {
        if (meta.dstPort !in MALWARE_PORTS) return

        emit(
            ThreatEvent(
                type        = "MALWARE_PORT",
                severity    = "HIGH",
                description = "Outbound connection to ${meta.dstIp}:${meta.dstPort} " +
                              "(protocol=${protoName(meta.protocol)}) — " +
                              "destination port is associated with common malware / RAT activity.",
                timestamp   = meta.timestamp
            )
        )
    }

    // -------------------------------------------------------------------------
    // Rule 2 — beacon detection
    // -------------------------------------------------------------------------

    private fun trackAndCheckBeacon(meta: PacketMeta) {
        // Normal DNS lookups to port 53 are inspected by DnsInspector and forwarded to
        // the upstream DNS resolver — repeated DNS lookups are expected, not C2 beaconing.
        if (meta.dstPort == PORT_DNS) return

        val dstIp = meta.dstIp
        val now   = meta.timestamp

        val timestamps = recentConnections.getOrPut(dstIp) { ArrayDeque() }

        // Append current hit
        timestamps.addLast(now)

        // Evict timestamps older than the beacon window
        val windowStart = now - BEACON_WINDOW_MS
        while (timestamps.isNotEmpty() && timestamps.first() < windowStart) {
            timestamps.removeFirst()
        }

        if (timestamps.size > BEACON_THRESHOLD) {
            Log.w(TAG, "Beacon candidate: $dstIp — ${timestamps.size} hits in ${BEACON_WINDOW_MS / 1000}s")
            emit(
                ThreatEvent(
                    type        = "BEACON",
                    severity    = "MEDIUM",
                    description = "${timestamps.size} connections to $dstIp within " +
                                  "${BEACON_WINDOW_MS / 1_000}s — possible C2 beaconing.",
                    timestamp   = now
                )
            )
            // Clear after emitting to avoid flooding on every subsequent packet
            timestamps.clear()
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /** Non-blocking emit — drops event only if internal buffer is full (should not happen). */
    private fun emit(event: ThreatEvent) {
        val enriched = enrichWithMl(event)
        val emitted  = _threatEvents.tryEmit(enriched)
        if (!emitted) Log.w(TAG, "ThreatEvent buffer full — dropped event: ${enriched.type}")
    }

    /**
     * Run [com.sentinelguard.ml.ThreatClassifier] on the event description and
     * attach the result as [ThreatEvent.mlLabel] / [ThreatEvent.mlScore].
     * Returns the original event unchanged if the classifier is unavailable or
     * returns [ThreatLabel.Benign] (saves allocating a copy for the common case).
     */
    private fun enrichWithMl(event: ThreatEvent): ThreatEvent {
        val clf    = ThreatClassifierHolder.classifier ?: return event
        val result = try { clf.classify(event.description) } catch (_: Exception) { return event }
        if (result.label == ThreatLabel.Benign) return event
        return event.copy(mlLabel = result.label.name, mlScore = result.confidence)
    }

    private fun protoName(proto: Int) = when (proto) {
        6    -> "TCP"
        17   -> "UDP"
        1    -> "ICMP"
        else -> proto.toString()
    }

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    companion object {
        private const val TAG = "ConnectionAnalyser"

        /** Maximum number of tracked destination IPs (eldest evicted beyond this). */
        private const val MAX_ENTRIES = 1_000

        /** Ports commonly associated with RATs, reverse shells, malware C2, and Tor. */
        val MALWARE_PORTS = setOf(4444, 5555, 6666, 1337, 31337, 8080, 8443, 9001, 9030)

        /** Connections-per-IP threshold within [BEACON_WINDOW_MS] to flag beaconing. */
        private const val BEACON_THRESHOLD = 8

        /** Sliding window for beacon detection (30 seconds). */
        private const val BEACON_WINDOW_MS = 30_000L

        /** DNS port excluded from C2 beacon tracking. */
        private const val PORT_DNS = 53

        /** Number of recent events replayed to new [threatEvents] collectors. */
        private const val FLOW_REPLAY = 10
    }
}
