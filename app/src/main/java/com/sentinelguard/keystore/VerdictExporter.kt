package com.sentinelguard.keystore

import android.content.Context
import com.sentinelguard.dns.SentinelDatabase
import java.text.SimpleDateFormat
import java.util.*

/**
 * [VerdictExporter] — serialises all [SignedVerdictEntity] rows from Room into
 * a JSON string suitable for audit / compliance export.
 *
 * Each entry includes:
 *   id, threatType, severity, confidence, timestamp (ISO-8601 UTC),
 *   mlLabel, content, signatureHex, publicKeyHex, hardwareVerified
 */
object VerdictExporter {

    private val isoFmt = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.US).apply {
        timeZone = TimeZone.getTimeZone("UTC")
    }

    /**
     * Load all verdicts from Room and return them serialised as a JSON array.
     * Must be called from a coroutine / suspend context.
     */
    suspend fun exportAsJson(context: Context): String {
        val db       = SentinelDatabase.getInstance(context)
        val verdicts = db.signedVerdictDao().getAll()

        val sb = StringBuilder("[\n")
        verdicts.forEachIndexed { index, v ->
            val timestampIso = isoFmt.format(Date(v.timestamp))
            val hardwareVerified = v.signatureHex.isNotEmpty()

            sb.append("  {\n")
            sb.append("    \"id\": ${v.id},\n")
            sb.append("    \"threatType\": ${jsonString(v.threatType)},\n")
            sb.append("    \"severity\": ${jsonString(v.severity)},\n")
            sb.append("    \"confidence\": ${v.confidence},\n")
            sb.append("    \"timestamp\": ${jsonString(timestampIso)},\n")
            sb.append("    \"mlLabel\": ${jsonString(v.mlLabel)},\n")
            sb.append("    \"content\": ${jsonString(v.content)},\n")
            sb.append("    \"signatureHex\": ${jsonString(v.signatureHex)},\n")
            sb.append("    \"publicKeyHex\": ${jsonString(v.publicKeyHex)},\n")
            sb.append("    \"hardwareVerified\": $hardwareVerified\n")
            sb.append("  }")
            if (index < verdicts.size - 1) sb.append(",")
            sb.append("\n")
        }
        sb.append("]")
        return sb.toString()
    }

    /** Escape a string value for JSON output. */
    private fun jsonString(value: String): String {
        val escaped = value
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
        return "\"$escaped\""
    }
}
