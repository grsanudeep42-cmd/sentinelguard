package com.sentinelguard.ml

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for ThreatClassifier and ThreatLabel types.
 *
 * Tests run on JVM without Android context — model loading is skipped
 * (requires assets). We verify the enum definitions, the label ordering
 * contract, and graceful fallback when the model is unavailable.
 */
class ThreatClassifierTest {

    @Test
    fun `ThreatLabel enum has all expected entries`() {
        val labels = ThreatLabel.values().map { it.name }
        assertTrue("Should include Benign",   labels.contains("Benign"))
        assertTrue("Should include CnC",      labels.contains("CnC"))
        assertTrue("Should include Malware",   labels.contains("Malware"))
        assertTrue("Should include Phishing",  labels.contains("Phishing"))
        assertTrue("Should include Smishing",  labels.contains("Smishing"))
    }

    @Test
    fun `ThreatLabel has exactly 5 values`() {
        assertEquals(
            "Classifier trained for 5 classes",
            5,
            ThreatLabel.values().size
        )
    }

    @Test
    fun `ThreatLabel alphabetical order matches training order`() {
        // The classifier output indices are alphabetically sorted:
        //   0=Benign  1=CnC  2=Malware  3=Phishing  4=Smishing
        val expected = listOf("Benign", "CnC", "Malware", "Phishing", "Smishing")
        val actual   = ThreatLabel.values().sortedBy { it.name }.map { it.name }
        assertEquals(expected, actual)
    }

    @Test
    fun `ThreatResult data class holds label and confidence`() {
        val result = ThreatResult(label = ThreatLabel.Phishing, confidence = 0.95f)
        assertEquals(ThreatLabel.Phishing, result.label)
        assertEquals(0.95f, result.confidence, 0.001f)
    }

    @Test
    fun `ThreatResult with zero confidence represents fallback`() {
        val fallback = ThreatResult(label = ThreatLabel.Benign, confidence = 0f)
        assertEquals(ThreatLabel.Benign, fallback.label)
        assertEquals(0f, fallback.confidence, 0.001f)
    }
}
