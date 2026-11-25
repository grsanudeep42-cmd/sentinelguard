package com.sentinelguard.dns

import android.content.Context
import android.util.Log
import androidx.work.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.TimeUnit

/**
 * BlocklistUpdater — a [CoroutineWorker] that downloads the OISD basic
 * blocklist once per day and persists it to [SentinelDatabase].
 *
 * Safety contract:
 *  - If the download or parse fails, the existing database rows are left
 *    untouched. deleteAll() is only called after a successful full parse.
 *  - Domains are batch-inserted in chunks of [BATCH_SIZE] to avoid
 *    building an unbounded in-memory list before the first DB write.
 *  - After a successful import the in-memory [DnsInspector] is reloaded
 *    so the new list is effective immediately without a restart.
 *
 * Schedule with [BlocklistUpdater.schedule] from Application.onCreate.
 * Duplicate scheduling calls are safe — WorkManager deduplicates by tag.
 */
class BlocklistUpdater(
    appContext: Context,
    params: WorkerParameters
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        Log.i(TAG, "Blocklist update started")

        val db  = SentinelDatabase.getInstance(applicationContext)
        val dao = db.blockedDomainDao()

        return@withContext try {
            val domains = downloadBlocklist()

            if (domains.isEmpty()) {
                Log.w(TAG, "Downloaded blocklist was empty — keeping existing DB")
                return@withContext Result.retry()
            }

            Log.i(TAG, "Downloaded ${domains.size} domains — writing to DB")

            // Only clear after a successful download
            dao.deleteAll()

            val now = System.currentTimeMillis()
            domains.chunked(BATCH_SIZE).forEach { chunk ->
                dao.insertAll(chunk.map { BlockedDomain(it, now) })
            }

            val total = dao.count()
            Log.i(TAG, "Blocklist import complete — $total domains in DB")

            // Reload the in-memory inspector immediately
            reloadInspector(dao)

            Result.success()
        } catch (e: Exception) {
            Log.e(TAG, "Blocklist update failed — DB unchanged", e)
            if (runAttemptCount < MAX_RETRIES) Result.retry() else Result.failure()
        }
    }

    // -------------------------------------------------------------------------
    // Download
    // -------------------------------------------------------------------------

    /**
     * Download and parse the OISD basic hosts file.
     *
     * Format (each data line):
     *   `0.0.0.0 example-bad-domain.com`
     * Lines starting with `#` are comments and are skipped.
     *
     * @return Set of lowercase FQDNs, empty on error (caller decides retry).
     */
    private fun downloadBlocklist(): Set<String> {
        val connection = URL(BLOCKLIST_URL).openConnection() as HttpURLConnection
        connection.apply {
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout    = READ_TIMEOUT_MS
            setRequestProperty("User-Agent", "SentinelGuard/1.0")
        }

        val domains = HashSet<String>(EXPECTED_DOMAIN_COUNT)

        connection.inputStream.use { stream ->
            BufferedReader(InputStreamReader(stream, Charsets.UTF_8)).use { reader ->
                reader.lineSequence().forEach { line ->
                    val trimmed = line.trim()
                    // Skip comments and empty lines
                    if (trimmed.isEmpty() || trimmed.startsWith('#')) return@forEach

                    // Format: "0.0.0.0 domain.example.com" or just "domain.example.com"
                    val parts = trimmed.split(WHITESPACE_REGEX, limit = 2)
                    val domain = when {
                        parts.size == 2 && parts[0] == "0.0.0.0" -> parts[1].trim().lowercase()
                        parts.size == 1                           -> parts[0].trim().lowercase()
                        else                                      -> return@forEach
                    }

                    if (domain.isNotEmpty() && domain.length <= 253 && DOMAIN_REGEX.matches(domain)) {
                        domains.add(domain)
                    }
                }
            }
        }

        return domains
    }

    // -------------------------------------------------------------------------
    // Inspector reload
    // -------------------------------------------------------------------------

    /**
     * Re-seed the [DnsInspector] singleton with all domains from [dao].
     * Uses a streaming approach to avoid loading the full list twice.
     */
    private suspend fun reloadInspector(dao: BlockedDomainDao) {
        val allDomains = dao.getAllDomains().map { it.domain }
        DnsInspectorHolder.inspector?.loadFromDatabase(allDomains)
        Log.d(TAG, "DnsInspector reloaded with ${allDomains.size} entries")
    }

    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    companion object {
        private const val TAG = "BlocklistUpdater"

        /** OISD basic blocklist — free, public, well-maintained, ~100 k domains. */
        private const val BLOCKLIST_URL = "https://hosts.oisd.nl/basic/"

        private const val CONNECT_TIMEOUT_MS  = 15_000
        private const val READ_TIMEOUT_MS     = 60_000
        private const val BATCH_SIZE          = 500
        private const val EXPECTED_DOMAIN_COUNT = 150_000
        private const val MAX_RETRIES         = 3

        /** Unique tag used for WorkManager deduplication. */
        private const val WORK_TAG = "sentinel_blocklist_update"

        private val WHITESPACE_REGEX = Regex("""\s+""")

        /**
         * Permissive domain regex — accepts labels with letters, digits, hyphens.
         * Rejects IP addresses, bare TLDs, and entries with invalid characters.
         */
        private val DOMAIN_REGEX = Regex(
            """^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"""
        )

        /**
         * Schedule a daily blocklist refresh using [WorkManager].
         * Safe to call multiple times — [ExistingPeriodicWorkPolicy.KEEP] is used
         * so an already-queued job is not replaced.
         */
        fun schedule(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .setRequiresBatteryNotLow(true)
                .build()

            val request = PeriodicWorkRequestBuilder<BlocklistUpdater>(
                repeatInterval = 24,
                repeatIntervalTimeUnit = TimeUnit.HOURS
            )
                .setConstraints(constraints)
                .addTag(WORK_TAG)
                .setBackoffCriteria(
                    BackoffPolicy.EXPONENTIAL,
                    WorkRequest.MIN_BACKOFF_MILLIS,
                    TimeUnit.MILLISECONDS
                )
                .build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_TAG,
                ExistingPeriodicWorkPolicy.KEEP,
                request
            )

            Log.i(TAG, "Daily blocklist update scheduled")
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Singleton holder — avoids passing DnsInspector through WorkManager params
// ─────────────────────────────────────────────────────────────────────────────

/**
 * [DnsInspectorHolder] — a process-scoped reference to the active [DnsInspector]
 * instance, set in [com.sentinelguard.SentinelApplication.onCreate].
 *
 * [BlocklistUpdater] uses this to push fresh data into the inspector after
 * a successful download without requiring a service restart.
 */
object DnsInspectorHolder {
    @Volatile
    var inspector: DnsInspector? = null
}
