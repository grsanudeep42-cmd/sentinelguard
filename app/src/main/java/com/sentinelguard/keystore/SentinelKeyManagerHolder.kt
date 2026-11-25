package com.sentinelguard.keystore

/**
 * [SentinelKeyManagerHolder] — process-scoped marker that records whether
 * [SentinelKeyManager] has been successfully initialised.
 *
 * Because [SentinelKeyManager] is a Kotlin `object` (singleton), it doesn't
 * need a holder reference in the same way that class-based singletons do.
 * This holder serves as:
 *   1. A consistent pattern across all SentinelGuard subsystems.
 *   2. A flag checked by [com.sentinelguard.keystore.VerdictLogger] to guard
 *      against signing attempts before Keystore initialisation completes.
 */
object SentinelKeyManagerHolder {

    /** True after [SentinelKeyManager.initialise] has completed without error. */
    @Volatile
    var isReady: Boolean = false
}
