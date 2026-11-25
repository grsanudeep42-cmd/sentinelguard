package com.sentinelguard.sms

/**
 * [ScamDetectorHolder] — process-scoped reference to the active [ScamDetector]
 * instance, set in [com.sentinelguard.SentinelApplication.onCreate].
 *
 * [SmsReceiver] and [SentinelNotificationListenerService] retrieve the
 * shared instance here so they don't each create their own detector (and
 * therefore their own independent [SharedFlow] subscriptions).
 */
object ScamDetectorHolder {
    @Volatile
    var detector: ScamDetector? = null
}
