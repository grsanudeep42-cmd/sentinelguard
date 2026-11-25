package com.sentinelguard.sms

import android.util.Log
import com.sentinelguard.ml.ThreatClassifierHolder
import com.sentinelguard.ml.ThreatLabel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlin.math.max
import kotlin.math.min

// ─────────────────────────────────────────────────────────────────────────────
// Result model
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Result of analysing a single SMS or notification message.
 *
 * @param isScam         True when [confidence] >= [ScamDetector.SCAM_THRESHOLD].
 * @param confidence     Weighted signal score clamped to [0.0, 1.0].
 * @param category       One of: "OTP_FRAUD", "BANK_FRAUD", "LOTTERY_SCAM",
 *                       "DELIVERY_SCAM", "KYC_SCAM", "CLEAN".
 * @param matchedSignals Human-readable labels for every signal that fired.
 * @param timestamp      Epoch-millisecond of analysis.
 */
data class ScamResult(
    val isScam:         Boolean,
    val confidence:     Float,
    val category:       String,
    val matchedSignals: List<String>,
    val timestamp:      Long
) {
    companion object {
        const val OTP_FRAUD     = "OTP_FRAUD"
        const val BANK_FRAUD    = "BANK_FRAUD"
        const val LOTTERY_SCAM  = "LOTTERY_SCAM"
        const val DELIVERY_SCAM = "DELIVERY_SCAM"
        const val KYC_SCAM      = "KYC_SCAM"
        const val CLEAN         = "CLEAN"
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Signal definitions
// ─────────────────────────────────────────────────────────────────────────────

/**
 * A single weighted detection signal.
 *
 * @param label   Human-readable name used in [ScamResult.matchedSignals].
 * @param weight  Contribution to total confidence score.
 * @param matches Predicate applied to the lower-cased message text.
 */
private data class Signal(
    val label:   String,
    val weight:  Float,
    val matches: (raw: String, lower: String) -> Boolean
)

// ─────────────────────────────────────────────────────────────────────────────
// ScamDetector
// ─────────────────────────────────────────────────────────────────────────────

/**
 * ScamDetector — a weighted, rule-based SMS / notification scam classifier.
 *
 * Detection pipeline per message:
 *   1. Apply all [Signal]s; accumulate matched weights.
 *   2. Clamp total to 1.0 → [ScamResult.confidence].
 *   3. If confidence >= [SCAM_THRESHOLD], derive the most specific [ScamResult.category].
 *   4. Emit via [results] SharedFlow; return synchronously.
 *
 * All matching is case-insensitive. Thread-safe (stateless per analysis call).
 */
class ScamDetector {

    // -------------------------------------------------------------------------
    // Output flow
    // -------------------------------------------------------------------------

    private val _results = MutableSharedFlow<ScamResult>(
        replay              = FLOW_REPLAY,
        extraBufferCapacity = 64
    )

    /** Hot [SharedFlow] of every [ScamResult] emitted. Collect from a coroutine. */
    val results: SharedFlow<ScamResult> = _results.asSharedFlow()

    // -------------------------------------------------------------------------
    // Signal table
    // -------------------------------------------------------------------------

    private val signals: List<Signal> = listOf(

        // ── 1. Urgency phrases (weight 0.30) ─────────────────────────────────
        Signal("URGENCY", 0.30f) { _, lower ->
            URGENCY_PHRASES.any { lower.contains(it) }
        },

        // ── 2. Financial / reward phrases (weight 0.30) ───────────────────────
        Signal("FINANCIAL", 0.30f) { _, lower ->
            FINANCIAL_PHRASES.any { lower.contains(it) }
        },

        // ── 3. Suspicious link patterns (weight 0.25) ─────────────────────────
        Signal("SUSPICIOUS_LINK", 0.25f) { raw, lower ->
            URL_REGEX.containsMatchIn(lower) ||
                    SHORTENER_REGEX.containsMatchIn(lower) ||
                    SUSPICIOUS_TLD_REGEX.containsMatchIn(lower)
        },

        // ── 4. OTP-related phrases (weight 0.20) ──────────────────────────────
        Signal("OTP_PATTERN", 0.20f) { _, lower ->
            OTP_PHRASES.any { lower.contains(it) }
        },

        // ── 5. Brand impersonation (weight 0.25) ──────────────────────────────
        Signal("IMPERSONATION", 0.25f) { _, lower ->
            IMPERSONATION_TOKENS.any { lower.contains(it) }
        },

        // ── 6. Grammar / encoding anomalies (weight 0.15) ────────────────────
        Signal("GRAMMAR_ANOMALY", 0.15f) { raw, _ ->
            excessiveCaps(raw) || excessivePunctuation(raw) || hasUnicodeLookalikes(raw)
        }
    )

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Analyse [message] and return a [ScamResult].
     * Also emits the result on [results] for async collectors.
     *
     * Pipeline:
     *   1. Rule-based weighted signals (regex / heuristics) → regexConfidence
     *   2. ThreatClassifier ML model (if loaded) → mlConfidence
     *   3. Combined confidence = max(regexConfidence, mlConfidence * ML_WEIGHT_BOOST)
     *   4. If combined >= SCAM_THRESHOLD → isScam = true
     */
    fun analyse(message: String): ScamResult {
        if (message.isBlank()) {
            return ScamResult(false, 0f, ScamResult.CLEAN, emptyList(), System.currentTimeMillis())
        }

        val lower = message.lowercase()
        val matched = mutableListOf<String>()
        var totalWeight = 0f

        for (signal in signals) {
            if (signal.matches(message, lower)) {
                matched.add(signal.label)
                totalWeight += signal.weight
            }
        }

        val regexConfidence = min(totalWeight, 1.0f)

        // ── ML enrichment via ThreatClassifier ───────────────────────────────
        val classifier = ThreatClassifierHolder.classifier
        var mlConfidence = 0f
        var mlLabel      = ""
        if (classifier != null && classifier.isLoaded) {
            val mlResult = classifier.classify(message)
            // Map Smishing / Phishing labels to scam confidence
            if (mlResult.label == ThreatLabel.Smishing || mlResult.label == ThreatLabel.Phishing) {
                mlConfidence = mlResult.confidence
                mlLabel      = mlResult.label.name
                matched.add("ML_${mlResult.label.name.uppercase()}")
            }
        }

        // Combined confidence: take the higher of regex or ML (boosted)
        val combinedConfidence = min(max(regexConfidence, mlConfidence * ML_WEIGHT_BOOST), 1.0f)
        val isScam             = combinedConfidence >= SCAM_THRESHOLD
        val category           = if (isScam) deriveCategory(lower, matched) else ScamResult.CLEAN

        val result = ScamResult(
            isScam         = isScam,
            confidence     = combinedConfidence,
            category       = category,
            matchedSignals = matched.toList(),
            timestamp      = System.currentTimeMillis()
        )

        _results.tryEmit(result)

        if (isScam) {
            Log.w(TAG, "Scam detected [$category] confidence=%.2f signals=$matched mlLabel=$mlLabel"
                .format(combinedConfidence))
        }

        return result
    }

    // -------------------------------------------------------------------------
    // Category derivation
    // ─────────────────────────────────────────────────────────────────────────
    // Priority order: more specific categories win over generic ones.

    private fun deriveCategory(lower: String, matched: List<String>): String {
        val hasOtp          = "OTP_PATTERN" in matched
        val hasFinancial    = "FINANCIAL" in matched
        val hasImpersonation = "IMPERSONATION" in matched
        val hasLink         = "SUSPICIOUS_LINK" in matched

        return when {
            // OTP fraud — message asks not to share a code
            hasOtp -> ScamResult.OTP_FRAUD

            // KYC scam — explicit KYC / Aadhaar reference
            lower.containsAny("kyc", "aadhaar", "uidai", "pan card") -> ScamResult.KYC_SCAM

            // Bank fraud — impersonation of a bank/wallet + financial signal
            hasImpersonation && hasFinancial ->
                if (lower.containsAny("sbi", "hdfc", "icici", "rbi", "npci", "paytm"))
                    ScamResult.BANK_FRAUD else ScamResult.LOTTERY_SCAM

            // Lottery / prize scam
            lower.containsAny("won", "winner", "prize", "lottery", "reward", "lucky draw") ->
                ScamResult.LOTTERY_SCAM

            // Delivery scam — package / parcel / courier
            lower.containsAny("delivery", "parcel", "shipment", "courier", "package",
                "out for delivery", "reschedule") ->
                ScamResult.DELIVERY_SCAM

            // Fallback — generic financial fraud
            hasFinancial || hasImpersonation -> ScamResult.BANK_FRAUD

            else -> ScamResult.BANK_FRAUD     // catch-all when scam=true
        }
    }

    // -------------------------------------------------------------------------
    // Grammar signal helpers
    // -------------------------------------------------------------------------

    /** True when > 30 % of alphabetic characters are uppercase. */
    private fun excessiveCaps(text: String): Boolean {
        val alphas = text.count { it.isLetter() }.takeIf { it > 0 } ?: return false
        val upper  = text.count { it.isUpperCase() }
        return (upper.toFloat() / alphas) > 0.30f
    }

    /** True when any run of the same punctuation character exceeds 3 in a row. */
    private fun excessivePunctuation(text: String): Boolean =
        EXCESS_PUNCT_REGEX.containsMatchIn(text)

    /**
     * True when the message contains common Unicode lookalike characters used
     * to evade keyword filters (e.g., Cyrillic 'а' instead of Latin 'a').
     */
    private fun hasUnicodeLookalikes(text: String): Boolean =
        text.any { it.code in LOOKALIKE_CODEPOINTS }

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    companion object {
        private const val TAG           = "ScamDetector"
        private const val FLOW_REPLAY   = 20

        /** Confidence threshold above which a message is classified as a scam. */
        const val SCAM_THRESHOLD = 0.45f

        /**
         * Multiplier applied to the ML model's confidence before combining with
         * the rule-based score. >1.0 so a strong ML signal can trigger detection
         * even when regex signals are absent (e.g. novel smishing with no keywords).
         */
        private const val ML_WEIGHT_BOOST = 1.2f

        // — Urgency —
        private val URGENCY_PHRASES = listOf(
            "urgent", "immediately", "expire", "expiring", "suspended",
            "suspend", "blocked", "block", "last chance", "act now",
            "action required", "24 hours", "48 hours", "within hours",
            "account will be", "will be deactivated", "will be blocked"
        )

        // — Financial / reward —
        private val FINANCIAL_PHRASES = listOf(
            "won", "prize", "reward", "cashback", "refund",
            "kyc", "verify account", "bank account", "wallet",
            "credit card", "debit card", "net banking", "upi",
            "click to claim", "claim now", "free gift", "you have been selected"
        )

        // — Link patterns —
        // Matches http(s):// URLs
        private val URL_REGEX = Regex("""https?://\S+""")
        // Matches popular URL shorteners
        private val SHORTENER_REGEX = Regex(
            """(?:bit\.ly|tinyurl\.com|t\.co|rb\.gy|ow\.ly|short\.io|goo\.gl|is\.gd|buff\.ly|adf\.ly)/\S+"""
        )
        // Matches suspicious TLDs often used in phishing
        private val SUSPICIOUS_TLD_REGEX = Regex(
            """\b\S+\.(?:tk|ml|ga|cf|gq|pw|top|xyz|icu|work|click|link|online|site|live|stream)\b"""
        )

        // — OTP —
        private val OTP_PHRASES = listOf(
            "otp", "one time password", "one-time password",
            "do not share", "never share", "dont share",
            "do not reveal", "confidential code", "verification code"
        )

        // — Impersonation tokens (lowercase) —
        private val IMPERSONATION_TOKENS = listOf(
            "sbi", "hdfc", "icici", "paytm", "npci", "rbi", "trai",
            "amazon", "flipkart", "uidai", "aadhaar", "irctc",
            "phonepe", "googlepay", "google pay", "mobikwik",
            "jio", "airtel", "vodafone", "bsnl"
        )

        // — Grammar signals —
        private val EXCESS_PUNCT_REGEX = Regex("""[!?.]{4,}""")

        /**
         * Unicode codepoints of common lookalike characters used in scam messages.
         * Sources: Unicode Consortium confusables data, abuse.ch reports.
         */
        private val LOOKALIKE_CODEPOINTS = setOf(
            0x0430, // Cyrillic 'а' (looks like Latin 'a')
            0x0435, // Cyrillic 'е' (looks like Latin 'e')
            0x043E, // Cyrillic 'о' (looks like Latin 'o')
            0x0440, // Cyrillic 'р' (looks like Latin 'p')
            0x0441, // Cyrillic 'с' (looks like Latin 'c')
            0x0445, // Cyrillic 'х' (looks like Latin 'x')
            0x2080, // Subscript zero
            0x2019, // Right single quotation mark (used to replace apostrophe)
            0xFF41, // Fullwidth Latin small letter a
            0xFF4F, // Fullwidth Latin small letter o
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// String extension helpers (file-private)
// ─────────────────────────────────────────────────────────────────────────────

/** Returns true if this string contains any of [terms] as a substring. */
private fun String.containsAny(vararg terms: String): Boolean =
    terms.any { this.contains(it) }
