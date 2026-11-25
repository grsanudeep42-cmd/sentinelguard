package com.sentinelguard.ml

/**
 * Process-scoped singleton reference to the active [ThreatClassifier].
 *
 * Set once by [com.sentinelguard.SentinelApplication.initThreatClassifier] on startup.
 * Nullable — a null value means the classifier failed to initialise (model absent or
 * native runtime error); callers must handle this gracefully and fall back to Benign.
 *
 * Access pattern mirrors [com.sentinelguard.dns.DnsInspectorHolder].
 */
object ThreatClassifierHolder {
    @Volatile
    var classifier: ThreatClassifier? = null
}
