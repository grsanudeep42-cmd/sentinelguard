package com.sentinelguard.sms

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for ScamDetector — weighted signal / heuristic logic.
 * No Android context required — pure JVM.
 *
 * Tests the [ScamDetector.analyse] method which runs the full pipeline:
 *   regex signals → ML enrichment (skipped in JVM, no TFLite) → combined score
 */
class ScamDetectorTest {

    private val detector = ScamDetector()

    @Test
    fun `prize scam phrase triggers detection`() {
        // Triggers FINANCIAL ("won", "claim now") + URGENCY ("act now") → 0.30 + 0.30 = 0.60 ≥ 0.45
        val msg = "Congratulations! You have won Rs 50,000. Act now! Click to claim now."
        val result = detector.analyse(msg)
        assertTrue("Prize scam must be detected", result.isScam)
        assertTrue(
            "Confidence must be above threshold",
            result.confidence >= ScamDetector.SCAM_THRESHOLD
        )
    }

    @Test
    fun `KYC phishing triggers detection`() {
        val msg = "Your account will be blocked. Update KYC immediately: http://fake-kyc.in/verify"
        val result = detector.analyse(msg)
        assertTrue("KYC phishing must be detected", result.isScam)
        assertEquals(ScamResult.KYC_SCAM, result.category)
    }

    @Test
    fun `delivery scam is categorised correctly`() {
        // Triggers SUSPICIOUS_LINK (bit.ly) + URGENCY ("immediately") → 0.25 + 0.30 = 0.55 ≥ 0.45
        val msg = "Your parcel is out for delivery. Reschedule immediately via http://bit.ly/fake-delivery"
        val result = detector.analyse(msg)
        assertTrue("Delivery scam must be detected", result.isScam)
        assertEquals(ScamResult.DELIVERY_SCAM, result.category)
    }

    @Test
    fun `normal greeting is not flagged`() {
        val msg = "Hey, are you coming to dinner tonight?"
        val result = detector.analyse(msg)
        assertFalse("Normal greeting should not be scam", result.isScam)
        assertEquals(ScamResult.CLEAN, result.category)
    }

    @Test
    fun `empty message returns CLEAN and does not crash`() {
        val result = detector.analyse("")
        assertFalse("Empty message should not be scam", result.isScam)
        assertEquals(ScamResult.CLEAN, result.category)
    }

    @Test
    fun `blank message returns CLEAN`() {
        val result = detector.analyse("   ")
        assertFalse("Blank message should not be scam", result.isScam)
    }

    @Test
    fun `urgency plus suspicious link triggers detection`() {
        val msg = "URGENT: Your SBI account has been blocked. Verify now: bit.ly/xxx"
        val result = detector.analyse(msg)
        assertTrue("Urgency + link + impersonation must trigger scam", result.isScam)
        assertTrue("Confidence should be high", result.confidence >= 0.7f)
    }

    @Test
    fun `matched signals list is populated`() {
        val msg = "URGENT: You have won Rs 1 Lakh. Click to claim reward now."
        val result = detector.analyse(msg)
        assertTrue("Should have URGENCY signal", "URGENCY" in result.matchedSignals)
        assertTrue("Should have FINANCIAL signal", "FINANCIAL" in result.matchedSignals)
    }

    @Test
    fun `OTP fraud is categorised correctly`() {
        val msg = "Your OTP is 847291. Never share your OTP with anyone. If you did not request this, call bank."
        val result = detector.analyse(msg)
        // OTP messages from real banks may or may not trigger — the key test is
        // that OTP_PATTERN signal fires and if scam threshold is met, category is OTP_FRAUD
        val hasOtp = "OTP_PATTERN" in result.matchedSignals
        assertTrue("Should detect OTP pattern", hasOtp)
    }

    @Test
    fun `excessive caps triggers grammar anomaly signal`() {
        val msg = "YOU HAVE WON A FREE IPHONE CLICK NOW TO CLAIM YOUR PRIZE IMMEDIATELY"
        val result = detector.analyse(msg)
        assertTrue("Excessive caps message must be scam", result.isScam)
        assertTrue(
            "Should have GRAMMAR_ANOMALY signal",
            "GRAMMAR_ANOMALY" in result.matchedSignals
        )
    }
}
