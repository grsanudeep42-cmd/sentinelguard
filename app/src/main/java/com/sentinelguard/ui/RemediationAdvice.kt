package com.sentinelguard.ui

// ─────────────────────────────────────────────────────────────────────────────
// RemediationAdvice — per-threat-type immediate action suggestions
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Maps a [threatType] string from [ThreatEvent] to a short, actionable
 * piece of advice that is shown immediately in the UI without needing the
 * Llama explainer to be loaded.
 *
 * Keep labels ≤ 36 characters so they fit on a single chip line.
 */
data class RemediationAdvice(
    /** Short imperative action — shown as a chip label. */
    val action: String,
    /** One-line explanation shown below the chip. */
    val detail: String,
    /** Urgency tier — drives chip colour. */
    val urgency: Urgency
) {
    enum class Urgency { CRITICAL, HIGH, MEDIUM, LOW }
}

object RemediationAdvisor {

    /**
     * Returns tailored [RemediationAdvice] for the given threat type.
     * Falls back to a generic advisory for unknown types.
     */
    fun advise(threatType: String, severity: String): RemediationAdvice {
        return when {
            // ── DNS / network threats ──────────────────────────────────────────
            threatType.contains("DNS", ignoreCase = true) ||
            threatType.contains("DOMAIN", ignoreCase = true) ->
                RemediationAdvice(
                    action  = "Block this domain",
                    detail  = "This domain matched a known malware/phishing blocklist. Avoid opening any links from it.",
                    urgency = RemediationAdvice.Urgency.HIGH
                )

            threatType.contains("C2", ignoreCase = true) ||
            threatType.contains("CNC", ignoreCase = true) ||
            threatType.contains("COMMAND", ignoreCase = true) ->
                RemediationAdvice(
                    action  = "Disconnect & scan device",
                    detail  = "Possible command-and-control contact detected. Run a full device security scan immediately.",
                    urgency = RemediationAdvice.Urgency.CRITICAL
                )

            threatType.contains("PORT", ignoreCase = true) ||
            threatType.contains("SCAN", ignoreCase = true) ->
                RemediationAdvice(
                    action  = "Review network connections",
                    detail  = "Unusual port activity detected. Check which apps have active network connections.",
                    urgency = RemediationAdvice.Urgency.MEDIUM
                )

            threatType.contains("MALWARE", ignoreCase = true) ->
                RemediationAdvice(
                    action  = "Uninstall suspicious apps",
                    detail  = "Malware behaviour pattern detected. Remove recently installed or sideloaded apps.",
                    urgency = RemediationAdvice.Urgency.CRITICAL
                )

            // ── SMS / communication threats ───────────────────────────────────
            threatType.contains("SMS", ignoreCase = true) ||
            threatType.contains("SCAM", ignoreCase = true) ->
                RemediationAdvice(
                    action  = "Delete SMS & block sender",
                    detail  = "This message matches known scam patterns. Do not click any links or reply.",
                    urgency = RemediationAdvice.Urgency.HIGH
                )

            threatType.contains("PHISHING", ignoreCase = true) ->
                RemediationAdvice(
                    action  = "Do not open the link",
                    detail  = "This URL is a known phishing attempt. If you clicked it, change your passwords immediately.",
                    urgency = RemediationAdvice.Urgency.CRITICAL
                )

            threatType.contains("OTP", ignoreCase = true) ||
            threatType.contains("BANK", ignoreCase = true) ||
            threatType.contains("UPI", ignoreCase = true) ->
                RemediationAdvice(
                    action  = "Never share OTPs",
                    detail  = "No legitimate bank or service ever asks for your OTP. Hang up or ignore this message.",
                    urgency = RemediationAdvice.Urgency.CRITICAL
                )

            threatType.contains("NOTIFICATION", ignoreCase = true) ->
                RemediationAdvice(
                    action  = "Dismiss & block app",
                    detail  = "Fraudulent notification pattern detected. Consider revoking notification permission for the sender.",
                    urgency = RemediationAdvice.Urgency.MEDIUM
                )

            // ── Connection / IP threats ───────────────────────────────────────
            threatType.contains("CONNECTION", ignoreCase = true) ||
            threatType.contains("IP", ignoreCase = true) ->
                RemediationAdvice(
                    action  = "Check active app connections",
                    detail  = "Suspicious outbound connection detected. Identify and kill the responsible app.",
                    urgency = RemediationAdvice.Urgency.HIGH
                )

            // ── Severity-based fallback ───────────────────────────────────────
            severity == "HIGH" ->
                RemediationAdvice(
                    action  = "Review immediately",
                    detail  = "High-severity threat detected. Check the Threat Log for details and take action now.",
                    urgency = RemediationAdvice.Urgency.HIGH
                )

            severity == "MEDIUM" ->
                RemediationAdvice(
                    action  = "Monitor closely",
                    detail  = "Suspicious activity detected. Keep an eye on this and avoid sharing sensitive information.",
                    urgency = RemediationAdvice.Urgency.MEDIUM
                )

            else ->
                RemediationAdvice(
                    action  = "Stay vigilant",
                    detail  = "Low-risk signal detected. No immediate action required.",
                    urgency = RemediationAdvice.Urgency.LOW
                )
        }
    }
}
