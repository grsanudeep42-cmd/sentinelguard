package com.sentinelguard

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import android.util.Log
import com.sentinelguard.dns.BlocklistUpdater
import com.sentinelguard.dns.DnsInspector
import com.sentinelguard.dns.DnsInspectorHolder
import com.sentinelguard.dns.SentinelDatabase
import com.sentinelguard.keystore.SentinelKeyManager
import com.sentinelguard.keystore.SentinelKeyManagerHolder
import com.sentinelguard.keystore.VerdictLogger
import com.sentinelguard.ml.LlamaExplainer
import com.sentinelguard.ml.LlamaExplainerHolder
import com.sentinelguard.ml.ThreatClassifier
import com.sentinelguard.ml.ThreatClassifierHolder
import com.sentinelguard.sms.ConnectionAnalyserHolder
import com.sentinelguard.sms.ScamDetector
import com.sentinelguard.sms.ScamDetectorHolder
import com.sentinelguard.sms.SmsReceiver
import com.sentinelguard.vpn.ConnectionAnalyser
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class SentinelApplication : Application() {

    /** Application-scoped coroutine scope — lives as long as the process. */
    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onCreate() {
        super.onCreate()
        createNotificationChannels()
        initConnectionAnalyser()    // must be first — others depend on the analyser
        initKeyManager()            // before VerdictLogger so signing is ready
        initDnsInspector()
        initScamDetector()
        initThreatClassifier()      // ML enrichment for all threat events
        initLlamaExplainer()        // on-demand LLM explanation (cheap — just checks file)
        startVerdictLogger()        // after ConnectionAnalyser + KeyManager are ready
        BlocklistUpdater.schedule(this)
    }

    // -------------------------------------------------------------------------
    // ConnectionAnalyser
    // -------------------------------------------------------------------------

    /**
     * Create the shared [ConnectionAnalyser] and expose it via
     * [ConnectionAnalyserHolder] so [SmsReceiver] and
     * [com.sentinelguard.sms.SentinelNotificationListenerService] can inject
     * threat events without holding a reference to [com.sentinelguard.vpn.SentinelVpnService].
     */
    private fun initConnectionAnalyser() {
        ConnectionAnalyserHolder.analyser = ConnectionAnalyser()
        Log.i(TAG, "ConnectionAnalyser initialised")
    }

    // -------------------------------------------------------------------------
    // Hardware Keystore
    // -------------------------------------------------------------------------

    /**
     * Initialise [SentinelKeyManager] on the IO thread (Keystore IPC may block).
     * Sets [SentinelKeyManagerHolder.isReady] to true once complete so
     * [VerdictLogger] knows it is safe to sign.
     */
    private fun initKeyManager() {
        appScope.launch {
            try {
                SentinelKeyManager.initialise()
                SentinelKeyManagerHolder.isReady = true
                val info = SentinelKeyManager.getAttestationInfo()
                Log.i(TAG, "KeyManager ready — StrongBox=${info.isStrongBox} " +
                           "TEE=${info.isTee} algo=${info.keyAlgorithm}")
            } catch (e: Exception) {
                Log.e(TAG, "KeyManager initialisation failed — verdicts will not be signed", e)
            }
        }
    }

    // -------------------------------------------------------------------------
    // DNS inspector
    // -------------------------------------------------------------------------

    /**
     * Create the [DnsInspector] singleton, register it in [DnsInspectorHolder],
     * and seed its in-memory blocklist from the Room database on the IO thread.
     *
     * First-launch path: if the DB is empty, the bundled `assets/blocklist.txt`
     * is parsed (StevenBlack hosts format) and all `0.0.0.0 <domain>` entries
     * are inserted into Room and loaded into memory in one pass.
     *
     * Subsequent launches: domains come straight from Room (fast path, no asset I/O).
     *
     * Runs asynchronously so it does not delay Application.onCreate.
     */
    private fun initDnsInspector() {
        val inspector = DnsInspector()
        DnsInspectorHolder.inspector = inspector

        appScope.launch {
            try {
                val dao     = SentinelDatabase.getInstance(applicationContext).blockedDomainDao()
                var domains = dao.getAllDomains().map { it.domain }

                if (domains.isEmpty()) {
                    Log.i(TAG, "DB empty — seeding from bundled blocklist asset")
                    domains = seedFromBundledBlocklist(dao)
                }

                inspector.loadFromDatabase(domains)
                Log.i(TAG, "DnsInspector seeded with ${domains.size} domains")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to seed DnsInspector — using built-in seeds only", e)
            }
        }
    }

    /**
     * Parse `assets/blocklist.txt` (StevenBlack/hosts format) and persist every
     * `0.0.0.0 <domain>` entry into Room in batches of [SEED_BATCH_SIZE].
     *
     * @return the full list of domain strings that were inserted.
     */
    private suspend fun seedFromBundledBlocklist(
        dao: com.sentinelguard.dns.BlockedDomainDao
    ): List<String> {
        val now     = System.currentTimeMillis()
        val domains = mutableListOf<String>()

        assets.open(BLOCKLIST_ASSET).bufferedReader().use { reader ->
            val batch = mutableListOf<com.sentinelguard.dns.BlockedDomain>()

            for (line in reader.lineSequence()) {
                // Skip comments, blank lines, and localhost/broadcast entries
                if (line.startsWith('#') || line.isBlank()) continue

                // Format: "0.0.0.0 some.domain.com [# optional comment]"
                if (!line.startsWith("0.0.0.0 ")) continue

                val domain = line
                    .removePrefix("0.0.0.0 ")
                    .substringBefore('#')
                    .trim()
                    .lowercase()

                if (domain.isBlank() || domain == "0.0.0.0") continue

                domains.add(domain)
                batch.add(com.sentinelguard.dns.BlockedDomain(domain = domain, addedAt = now))

                if (batch.size >= SEED_BATCH_SIZE) {
                    dao.insertAll(batch)
                    batch.clear()
                }
            }

            // Insert any remaining entries
            if (batch.isNotEmpty()) dao.insertAll(batch)
        }

        // Record seed timestamp so the UI shows "Last Updated"
        getSharedPreferences(com.sentinelguard.vpn.BootReceiver.PREFS_NAME, MODE_PRIVATE)
            .edit()
            .putLong(PREF_BLOCKLIST_UPDATED, now)
            .apply()

        Log.i(TAG, "Bundled blocklist seeded: ${domains.size} domains → Room")
        return domains
    }

    // -------------------------------------------------------------------------
    // Scam detector
    // -------------------------------------------------------------------------

    /**
     * Create the [ScamDetector] singleton and register it in [ScamDetectorHolder].
     * Fully synchronous — no DB seeding required.
     */
    private fun initScamDetector() {
        ScamDetectorHolder.detector = ScamDetector()
        Log.i(TAG, "ScamDetector initialised")
    }

    // -------------------------------------------------------------------------
    // ML — TFLite threat classifier
    // -------------------------------------------------------------------------

    /**
     * Initialises [ThreatClassifier] on the IO thread.
     * If `assets/threat_classifier.tflite` is absent the classifier degrades
     * gracefully — [ThreatClassifier.isLoaded] will return false and every
     * call to [ThreatClassifier.classify] returns `ThreatLabel.Benign / 0f`.
     */
    private fun initThreatClassifier() {
        appScope.launch {
            try {
                val clf = ThreatClassifier(applicationContext)
                ThreatClassifierHolder.classifier = clf
                Log.i(TAG, "ThreatClassifier ready — model loaded: ${clf.isLoaded}")
            } catch (e: Exception) {
                Log.e(TAG, "ThreatClassifier init failed", e)
            }
        }
    }

    // -------------------------------------------------------------------------
    // ML — Llama 3.2 1B Instruct explainer (ExecuTorch + XNNPACK)
    // -------------------------------------------------------------------------

    /**
     * Constructs [LlamaExplainer] (cheap — only checks file existence).
     * The model is NOT bundled in the APK; it must be pushed via adb.
     * [LlamaExplainer.isAvailable] will return false when the model files
     * are absent and the UI "Explain with AI" button will not be shown.
     */
    private fun initLlamaExplainer() {
        LlamaExplainerHolder.explainer = LlamaExplainer(applicationContext)
        Log.i(TAG, "LlamaExplainer initialised — available: ${LlamaExplainerHolder.explainer?.isAvailable}")
    }

    // -------------------------------------------------------------------------
    // Verdict logger
    // -------------------------------------------------------------------------

    /**
     * Start the [VerdictLogger] coroutine collector.
     * Requires [ConnectionAnalyserHolder] to be populated (done in [initConnectionAnalyser]).
     * Signing readiness is checked lazily inside [VerdictLogger] per event.
     */
    private fun startVerdictLogger() {
        VerdictLogger.start(applicationContext)
        Log.i(TAG, "VerdictLogger started")
    }

    // -------------------------------------------------------------------------
    // Notification channels
    // -------------------------------------------------------------------------

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return

        val nm = getSystemService(NotificationManager::class.java)

        // VPN status — low importance, persistent
        val vpnChannel = NotificationChannel(
            CHANNEL_VPN,
            getString(R.string.vpn_channel_name),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = getString(R.string.vpn_channel_description)
            setShowBadge(false)
        }

        // Threat alerts — high importance, heads-up
        val alertChannel = NotificationChannel(
            SmsReceiver.CHANNEL_ALERTS,
            getString(R.string.alerts_channel_name),
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = getString(R.string.alerts_channel_description)
            enableVibration(true)
            setShowBadge(true)
        }

        nm.createNotificationChannels(listOf(vpnChannel, alertChannel))
    }

    companion object {
        private const val TAG = "SentinelApplication"
        const val CHANNEL_VPN = "sentinel_vpn_channel"

        /** Asset file name of the bundled StevenBlack hosts blocklist. */
        private const val BLOCKLIST_ASSET = "blocklist.txt"

        /** Rows inserted per Room transaction during first-launch asset seeding. */
        private const val SEED_BATCH_SIZE = 500

        /**
         * SharedPreferences key recording when the blocklist was last populated.
         * Written by [seedFromBundledBlocklist] and by [com.sentinelguard.dns.BlocklistUpdater].
         * Read by [com.sentinelguard.ui.MainViewModel] to show "Last Updated".
         */
        const val PREF_BLOCKLIST_UPDATED = "blocklist_last_updated"
    }
}
