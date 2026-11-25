package com.sentinelguard.dns

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for DnsInspector — hostname classification via blocklist,
 * suffix trie, and Shannon entropy heuristics.
 *
 * Tests run on JVM without Android context — the DnsInspector is instantiated
 * directly (no asset loading). We test the classification pipeline that
 * doesn't require DNS packet parsing.
 */
class DnsInspectorTest {

    private lateinit var inspector: DnsInspector

    @Before
    fun setUp() {
        inspector = DnsInspector()
    }

    @Test
    fun `safe domain is not flagged as malicious`() {
        val result = inspector.checkHostname("google.com")
        // google.com is not in the blocklist, not a free TLD, and not high-entropy
        if (result != null) {
            assertFalse("google.com should not be malicious", result.isMalicious)
        }
    }

    @Test
    fun `high-entropy DGA-like domain is flagged`() {
        // 32-char hex-looking subdomain → high Shannon entropy → DGA heuristic
        val dgaDomain = "a3f9b2c1d4e5f6a7b8c9d0e1f2a3b4c5.evil.com"
        val result = inspector.checkHostname(dgaDomain)
        // We expect the entropy heuristic to fire (domain length > 20 and entropy > 3.5)
        assertNotNull("DGA domain must return a result", result)
        assertTrue("DGA domain should be flagged as malicious", result!!.isMalicious)
        assertEquals(DnsResult.HIGH_ENTROPY_DGA, result.category)
    }

    @Test
    fun `known seed blocklist domain is flagged as KNOWN_MALICIOUS`() {
        // "iplogger.org" is in the seed blocklist hardcoded in DnsInspector
        val result = inspector.checkHostname("iplogger.org")
        assertNotNull("Seed domain must return a result", result)
        assertTrue("Seed domain must be malicious", result!!.isMalicious)
        assertEquals(DnsResult.KNOWN_MALICIOUS, result.category)
    }

    @Test
    fun `subdomain of blocklisted domain is flagged as KNOWN_MALICIOUS`() {
        val result = inspector.checkHostname("track.iplogger.org")
        assertNotNull("Subdomain must return a result", result)
        assertTrue("Subdomain of blocked host must be malicious", result!!.isMalicious)
        assertEquals(DnsResult.KNOWN_MALICIOUS, result.category)
    }

    @Test
    fun `suspicious TLD domain is flagged`() {
        // ".tk" is in the suffix trie as an abused free TLD
        val result = inspector.checkHostname("evil-phishing.tk")
        assertNotNull("Suspicious TLD domain must return a result", result)
        assertTrue("Suspicious TLD domain must be malicious", result!!.isMalicious)
        assertEquals(DnsResult.SUSPICIOUS_TLD, result.category)
    }

    @Test
    fun `checkHostname handles empty string without crash`() {
        val result = inspector.checkHostname("")
        assertNull("Empty string should return null", result)
    }

    @Test
    fun `checkHostname handles blank string without crash`() {
        val result = inspector.checkHostname("   ")
        assertNull("Blank string should return null", result)
    }

    @Test
    fun `clean domain is classified as CLEAN`() {
        val result = inspector.checkHostname("stackoverflow.com")
        assertNotNull("Non-null result expected", result)
        assertFalse("stackoverflow.com should be clean", result!!.isMalicious)
        assertEquals(DnsResult.CLEAN, result.category)
    }

    @Test
    fun `legitimate long multi-label domain is not flagged as DGA`() {
        listOf(
            "z-m-gateway.facebook.com",
            "sentry-prod.branch.io",
            "geomobileservices-pa.googleapis.com"
        ).forEach { host ->
            val result = inspector.checkHostname(host)
            assertNotNull("$host should return a result", result)
            assertFalse("$host must not be false-flagged as DGA", result!!.isMalicious)
            assertEquals(DnsResult.CLEAN, result.category)
        }
    }
}
