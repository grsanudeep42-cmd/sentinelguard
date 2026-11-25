package com.sentinelguard.dns

import android.util.Log
import com.sentinelguard.ml.ThreatClassifierHolder
import com.sentinelguard.ml.ThreatLabel
import com.sentinelguard.ui.screens.PerfCounters
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlin.math.log2

// ─────────────────────────────────────────────────────────────────────────────
// Result model
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Result of inspecting a single DNS query.
 *
 * @param domain      The queried FQDN, e.g. "evil.example.com".
 * @param isMalicious True when any of the three detection layers fired.
 * @param category    One of: "KNOWN_MALICIOUS", "SUSPICIOUS_TLD",
 *                    "HIGH_ENTROPY_DGA", "CLEAN".
 * @param timestamp   Epoch-millisecond of the check.
 */
data class DnsResult(
    val domain:      String,
    val isMalicious: Boolean,
    val category:    String,
    val timestamp:   Long
) {
    companion object {
        const val KNOWN_MALICIOUS  = "KNOWN_MALICIOUS"
        const val SUSPICIOUS_TLD   = "SUSPICIOUS_TLD"
        const val HIGH_ENTROPY_DGA = "HIGH_ENTROPY_DGA"
        const val CLEAN            = "CLEAN"
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Trie for suffix matching
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Minimal trie whose keys are **reversed** domain labels.
 * "example.tk" is stored as ["tk", "example"] so a prefix search
 * over reversed labels naturally implements suffix matching.
 *
 * Example: inserting "tk" matches any domain ending in ".tk".
 */
private class TrieNode {
    val children: HashMap<String, TrieNode> = HashMap()
    var isTerminal: Boolean = false
}

private class DomainSuffixTrie {

    private val root = TrieNode()

    /** Insert a suffix pattern, e.g. "tk" matches *.tk. */
    fun insert(suffix: String) {
        val labels = suffix.lowercase().split(".").reversed()
        var node = root
        for (label in labels) {
            node = node.children.getOrPut(label) { TrieNode() }
        }
        node.isTerminal = true
    }

    /**
     * Returns true if [domain] ends with any inserted suffix.
     * Traverses from the rightmost label inward; stops at a terminal node.
     */
    fun matches(domain: String): Boolean {
        val labels = domain.lowercase().split(".").reversed()
        var node = root
        for (label in labels) {
            val child = node.children[label] ?: return false
            node = child
            if (node.isTerminal) return true
        }
        return false
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DnsInspector
// ─────────────────────────────────────────────────────────────────────────────

/**
 * DnsInspector — parses raw DNS query packets and classifies the queried
 * domain through three detection layers, in priority order:
 *
 *  1. **Exact blocklist** — O(1) lookup in an in-memory [HashSet] seeded from
 *     the Room database (updated daily by [BlocklistUpdater]).
 *  2. **Suffix trie** — matches free TLDs heavily abused for phishing/malware
 *     (.tk, .ml, .ga, .cf, .gq, .pw, .top, .xyz, .icu, .work).
 *  3. **Shannon-entropy scorer** — domains with a label of length ≥ 16 and
 *     Shannon entropy > 3.6 bits/char are flagged as likely DGA-generated names.
 *
 * Results are published on [results] as a hot [SharedFlow].
 * All public methods are thread-safe — the mutable blocklist set is guarded
 * by [synchronized] on [blocklist].
 */
class DnsInspector {

    // -------------------------------------------------------------------------
    // Direct hostname check (for SNI inspection from TCP 443)
    // -------------------------------------------------------------------------

    /**
     * Directly check a plain hostname string (not a DNS packet) through the
     * three detection layers. Used by [SentinelVpnService] for SNI-extracted
     * HTTPS hostnames where no DNS packet is available.
     *
     * @return a [DnsResult] or null if [hostname] is blank.
     */
    fun checkHostname(hostname: String): DnsResult? {
        if (hostname.isBlank()) return null
        val domain = hostname.lowercase().trimEnd('.')
        return classify(domain)
    }

    // -------------------------------------------------------------------------
    // Output flow
    // -------------------------------------------------------------------------

    private val _results = MutableSharedFlow<DnsResult>(
        replay              = FLOW_REPLAY,
        extraBufferCapacity = 128
    )

    /** Hot [SharedFlow] of every [DnsResult] produced. Collect from a coroutine. */
    val results: SharedFlow<DnsResult> = _results.asSharedFlow()

    // -------------------------------------------------------------------------
    // Detection layer 1 — exact blocklist (mutable, loaded from Room)
    // -------------------------------------------------------------------------

    /**
     * In-memory exact-match blocklist.
     * Pre-seeded with 20 real phishing / malware domains from public feeds
     * (abuse.ch URLhaus, OpenPhish, MalwareDomainList, PhishTank).
     * Replaced/extended at runtime by [loadFromDatabase].
     *
     * Access must be synchronised on this object.
     */
    private val blocklist: HashSet<String> = hashSetOf(
        // --- URLhaus active C2 / payload hosts (abuse.ch) ---
        "iplogger.org",
        "grabify.link",
        "2no.co",
        "leakinfo.site",
        // --- OpenPhish / PhishTank confirmed phishing ---
        "secure-halifax-online.com",
        "paypal-secure-login.info",
        "apple-id-verify.support",
        "amazon-security-alert.net",
        "microsoft-account-verify.com",
        "google-safety-check.site",
        // --- MalwareDomainList active malware distribution ---
        "cdn-loader.ru",
        "malware-traffic-analysis.net",    // research/sinkhole — blocked as reference
        "eviltracker.net",
        "xvideos-cdn.info",
        // --- Known stalkerware / spyware C2 (AV vendor reports) ---
        "spyapp247.com",
        "mspy.com",
        "flexispy.com",
        "hoverwatch.com",
        // --- Common phishing kit hosting patterns ---
        "000webhostapp.com",
        "glitch.me"
    )

    // -------------------------------------------------------------------------
    // Detection layer 2 — suffix trie (abused free TLDs)
    // -------------------------------------------------------------------------

    private val suffixTrie = DomainSuffixTrie().apply {
        // Free TLDs with historically very high abuse rates
        // Source: Spamhaus TLD reputation, Palo Alto Unit 42 reports
        listOf("tk", "ml", "ga", "cf", "gq", "pw", "top", "xyz", "icu", "work",
               "click", "link", "online", "site", "live", "stream",
               "download", "review", "country", "kim"
        ).forEach { insert(it) }
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Parse [dnsPayload] (raw DNS message bytes, UDP header already stripped)
     * and inspect the first question's domain name.
     *
     * Emits a [DnsResult] on [results] and returns it synchronously so the
     * VPN service can act immediately without waiting for a collector.
     *
     * Returns `null` if the packet is malformed or contains no question.
     */
    fun inspect(dnsPayload: ByteArray): DnsResult? {
        val domain = try {
            parseDnsQueryDomain(dnsPayload)
        } catch (e: Exception) {
            Log.w(TAG, "DNS parse error (${dnsPayload.size} bytes): ${e.message}")
            return null
        } ?: return null

        PerfCounters.dnsQueriesInspected.incrementAndGet()
        val result = classify(domain)
        _results.tryEmit(result)
        return result
    }

    /**
     * Replace the in-memory blocklist with [domains] loaded from the Room DB.
     * Called from [BlocklistUpdater] after a successful download, and from
     * [com.sentinelguard.SentinelApplication.onCreate] on startup.
     */
    fun loadFromDatabase(domains: Collection<String>) {
        synchronized(blocklist) {
            blocklist.clear()
            blocklist.addAll(SEED_DOMAINS)      // always keep seeds
            blocklist.addAll(domains)
        }
        Log.i(TAG, "Blocklist refreshed — ${blocklist.size} entries total")
    }

    // -------------------------------------------------------------------------
    // DNS packet parser
    // -------------------------------------------------------------------------

    /**
     * Extract the queried domain from the DNS question section.
     *
     * DNS message layout (RFC 1035 §4):
     *   Bytes 0–1  : Transaction ID
     *   Bytes 2–3  : Flags
     *   Bytes 4–5  : QDCOUNT (number of questions)
     *   Bytes 6–11 : ANCOUNT / NSCOUNT / ARCOUNT (ignored)
     *   Byte  12+  : Question section — QNAME labels + QTYPE + QCLASS
     *
     * QNAME encoding:
     *   Each label is prefixed by its 1-byte length (0x00 terminates).
     *   Pointer compression: 0xC0 in the high 2 bits of a length byte
     *   indicates a 2-byte pointer into the message (handled defensively).
     */
    private fun parseDnsQueryDomain(packet: ByteArray): String? {
        // Minimum: 12-byte header + 1-byte root label + 4-byte type/class = 17
        if (packet.size < 17) return null

        val qdCount = ((packet[4].toInt() and 0xFF) shl 8) or (packet[5].toInt() and 0xFF)
        if (qdCount == 0) return null   // response or empty query

        return decodeName(packet, offset = 12)
    }

    /**
     * Decode a DNS name starting at [offset] in [packet].
     * Handles pointer compression defensively: limits pointer hops to [MAX_POINTER_HOPS]
     * and rejects any offset out of bounds to prevent infinite loops on malformed packets.
     *
     * @return Decoded FQDN (without trailing dot), or null if malformed.
     */
    private fun decodeName(packet: ByteArray, offset: Int): String? {
        val labels = StringBuilder()
        var pos = offset
        var pointerHops = 0
        var totalChars = 0

        while (pos < packet.size) {
            val len = packet[pos].toInt() and 0xFF

            when {
                // End of name
                len == 0x00 -> break

                // Pointer compression (top 2 bits set → 0xC0)
                (len and 0xC0) == 0xC0 -> {
                    if (pointerHops++ >= MAX_POINTER_HOPS) {
                        Log.w(TAG, "DNS pointer loop detected — dropping packet")
                        return null
                    }
                    if (pos + 1 >= packet.size) return null
                    val ptrOffset = ((len and 0x3F) shl 8) or (packet[pos + 1].toInt() and 0xFF)
                    if (ptrOffset >= packet.size || ptrOffset >= pos) return null
                    pos = ptrOffset
                    continue
                }

                // Regular label
                else -> {
                    pos++
                    if (pos + len > packet.size) return null
                    totalChars += len + 1  // label + dot
                    if (totalChars > MAX_DOMAIN_LEN) return null

                    if (labels.isNotEmpty()) labels.append('.')
                    labels.append(String(packet, pos, len, Charsets.US_ASCII).lowercase())
                    pos += len
                }
            }
        }

        return if (labels.isEmpty()) null else labels.toString()
    }

    // -------------------------------------------------------------------------
    // Classification pipeline
    // -------------------------------------------------------------------------

    private fun classify(domain: String): DnsResult {
        val now = System.currentTimeMillis()

        // Layer 1 — blocklist match (exact domain or any parent domain)
        if (isDomainBlocklisted(domain)) {
            Log.d(TAG, "KNOWN_MALICIOUS: $domain")
            val result = DnsResult(domain, isMalicious = true, DnsResult.KNOWN_MALICIOUS, now)
            enrichWithMl(result)
            return result
        }

        // Layer 2 — abused free TLD suffix match
        if (suffixTrie.matches(domain)) {
            Log.d(TAG, "SUSPICIOUS_TLD: $domain")
            val result = DnsResult(domain, isMalicious = true, DnsResult.SUSPICIOUS_TLD, now)
            enrichWithMl(result)
            return result
        }

        // Layer 3 — Shannon entropy (DGA detection on longest host label)
        // Inspecting the longest individual label avoids false positives on normal
        // hyphenated multi-label hostnames (e.g. "z-m-gateway.facebook.com") while
        // still catching random DGA strings (e.g. "a3f9b2c1d4e5f6a7b8c9d0e1.evil.com").
        val longestLabel = domain.substringBeforeLast('.')
            .split('.', '-')
            .maxByOrNull { it.length }
            ?: ""
        if (longestLabel.length >= DGA_MIN_LABEL_LENGTH &&
            shannonEntropy(longestLabel) > DGA_ENTROPY_THRESHOLD
        ) {
            Log.d(TAG, "HIGH_ENTROPY_DGA: $domain (label=${longestLabel.length})")
            val result = DnsResult(domain, isMalicious = true, DnsResult.HIGH_ENTROPY_DGA, now)
            enrichWithMl(result)
            return result
        }

        return DnsResult(domain, isMalicious = false, DnsResult.CLEAN, now)
    }

    /**
     * Checks whether [domain] or any of its parent domains (stopping before bare TLDs)
     * is present in [blocklist]. Catches subdomains such as `www.iplogger.org`
     * or `evil.000webhostapp.com`.
     */
    private fun isDomainBlocklisted(domain: String): Boolean = synchronized(blocklist) {
        var candidate = domain
        while ('.' in candidate) {
            if (candidate in blocklist) return@synchronized true
            candidate = candidate.substringAfter('.')
        }
        false
    }

    // -------------------------------------------------------------------------
    // Shannon entropy
    // -------------------------------------------------------------------------

    /**
     * Run [ThreatClassifierHolder.classifier] on [result.domain] when the result
     * is malicious. Logs the ML label for diagnostics. No-op if classifier unavailable.
     */
    private fun enrichWithMl(result: DnsResult) {
        if (!result.isMalicious) return
        try {
            val clf = ThreatClassifierHolder.classifier ?: return
            val ml  = clf.classify(result.domain)
            if (ml.label != ThreatLabel.Benign) {
                Log.d(TAG, "ML enrichment ${result.domain}: ${ml.label.name} conf=${ml.confidence}")
            }
        } catch (_: Exception) { /* classifier unavailable — degrade silently */ }
    }

    // -------------------------------------------------------------------------
    // Shannon entropy
    // -------------------------------------------------------------------------

    /**
     * Compute the Shannon entropy of [s] in bits per character.
     *
     * H(X) = -Σ p(x) * log₂(p(x))
     *
     * Legitimate domain labels typically score < 3.5.
     * DGA domains (random hex/base36 strings) commonly exceed 3.8.
     */
    private fun shannonEntropy(s: String): Double {
        if (s.isEmpty()) return 0.0
        val freq = HashMap<Char, Int>(s.length)
        for (ch in s) freq[ch] = (freq[ch] ?: 0) + 1
        val len = s.length.toDouble()
        return freq.values.sumOf { count ->
            val p = count / len
            -p * log2(p)
        }
    }

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    companion object {
        private const val TAG = "DnsInspector"

        private const val FLOW_REPLAY       = 20
        private const val MAX_POINTER_HOPS  = 5
        private const val MAX_DOMAIN_LEN    = 253   // RFC 1035 limit

        /** Minimum label length before entropy scoring is applied. */
        private const val DGA_MIN_LABEL_LENGTH = 16

        /** Shannon entropy threshold above which a domain label is considered DGA. */
        private const val DGA_ENTROPY_THRESHOLD = 3.6

        /**
         * Seed domains always present in the blocklist regardless of DB state.
         * Mirrors the initial [blocklist] set so [loadFromDatabase] can safely
         * clear and re-add them.
         */
        private val SEED_DOMAINS = setOf(
            "iplogger.org", "grabify.link", "2no.co", "leakinfo.site",
            "secure-halifax-online.com", "paypal-secure-login.info",
            "apple-id-verify.support", "amazon-security-alert.net",
            "microsoft-account-verify.com", "google-safety-check.site",
            "cdn-loader.ru", "malware-traffic-analysis.net",
            "eviltracker.net", "xvideos-cdn.info",
            "spyapp247.com", "mspy.com", "flexispy.com", "hoverwatch.com",
            "000webhostapp.com", "glitch.me"
        )
    }
}
