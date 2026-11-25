package com.sentinelguard.dns

import androidx.room.*
import com.sentinelguard.keystore.SignedVerdictDao
import com.sentinelguard.keystore.SignedVerdictEntity

// ─────────────────────────────────────────────────────────────────────────────
// Entity
// ─────────────────────────────────────────────────────────────────────────────

/**
 * [BlockedDomain] — a single entry in the persistent blocklist.
 *
 * @param domain  Fully-qualified domain name (lowercase, no trailing dot).
 * @param addedAt Epoch-millisecond of insertion — used for staleness checks.
 */
@Entity(tableName = "blocked_domains")
data class BlockedDomain(
    @PrimaryKey
    val domain: String,
    val addedAt: Long
)

// ─────────────────────────────────────────────────────────────────────────────
// DAO
// ─────────────────────────────────────────────────────────────────────────────

@Dao
interface BlockedDomainDao {

    /**
     * Insert or replace a [BlockedDomain]. REPLACE strategy silently updates
     * [addedAt] when a domain appears in an updated blocklist download.
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(domain: BlockedDomain)

    /**
     * Bulk-insert a list of [BlockedDomain] entries in a single transaction.
     * Used during blocklist import to minimise write amplification.
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(domains: List<BlockedDomain>)

    /** Return every domain in the table — loaded at startup into the in-memory set. */
    @Query("SELECT * FROM blocked_domains")
    suspend fun getAllDomains(): List<BlockedDomain>

    /** Return the total count — useful for logging / UI diagnostics. */
    @Query("SELECT COUNT(*) FROM blocked_domains")
    suspend fun count(): Long

    /**
     * Delete all rows — called only before a successful full blocklist refresh,
     * never on download failure.
     */
    @Query("DELETE FROM blocked_domains")
    suspend fun deleteAll()
}

// ─────────────────────────────────────────────────────────────────────────────
// Database
// ─────────────────────────────────────────────────────────────────────────────

/**
 * [SentinelDatabase] — single Room database for SentinelGuard.
 *
 * Version history:
 *   1 → initial schema (blocked_domains)
 *   2 → added signed_verdicts table
 *   3 → signed_verdicts gains mlLabel + explanation columns
 *   4 → signed_verdicts gains content column
 *        (stores the raw detected content — domain, SMS text, etc. — for
 *        display in the expanded ThreatLog row and as Llama explainer context)
 *
 * Access via [SentinelDatabase.getInstance] — the singleton is created once
 * and reused for the lifetime of the application process.
 */
@Database(
    entities = [BlockedDomain::class, SignedVerdictEntity::class],
    version = 4,
    exportSchema = false
)
abstract class SentinelDatabase : RoomDatabase() {

    abstract fun blockedDomainDao(): BlockedDomainDao
    abstract fun signedVerdictDao(): SignedVerdictDao

    companion object {
        @Volatile
        private var INSTANCE: SentinelDatabase? = null

        fun getInstance(context: android.content.Context): SentinelDatabase =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    SentinelDatabase::class.java,
                    "sentinel_db"
                )
                    .fallbackToDestructiveMigration()   // safe for dev; replace with Migration objects before release
                    .build()
                    .also { INSTANCE = it }
            }
    }
}
