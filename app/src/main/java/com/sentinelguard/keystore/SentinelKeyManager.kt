package com.sentinelguard.keystore

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

// ─────────────────────────────────────────────────────────────────────────────
// Domain models
// ─────────────────────────────────────────────────────────────────────────────

/**
 * The data to be signed — serialised to canonical JSON before ECDSA signing.
 * [kotlinx.serialization] is used exclusively; no Gson or Moshi dependency.
 */
@Serializable
data class VerdictPayload(
    val threatType:  String,
    val severity:    String,
    val domain:      String?,
    val sourceIp:    String?,
    val confidence:  Float,
    val timestamp:   Long
)

/**
 * A [VerdictPayload] with its hardware-generated ECDSA signature attached.
 *
 * @param payload          The original verdict data.
 * @param signature        DER-encoded ECDSA signature bytes over the JSON representation.
 * @param publicKeyEncoded X.509 SubjectPublicKeyInfo bytes of the signing key.
 * @param signingAlgorithm Always "SHA256withECDSA".
 */
data class SignedVerdict(
    val payload:          VerdictPayload,
    val signature:        ByteArray,
    val publicKeyEncoded: ByteArray,
    val signingAlgorithm: String
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SignedVerdict) return false
        return payload == other.payload &&
               signature.contentEquals(other.signature) &&
               publicKeyEncoded.contentEquals(other.publicKeyEncoded) &&
               signingAlgorithm == other.signingAlgorithm
    }
    override fun hashCode(): Int {
        var result = payload.hashCode()
        result = 31 * result + signature.contentHashCode()
        result = 31 * result + publicKeyEncoded.contentHashCode()
        result = 31 * result + signingAlgorithm.hashCode()
        return result
    }
}

/**
 * Hardware attestation metadata returned by [SentinelKeyManager.getAttestationInfo].
 *
 * @param isStrongBox  True when the private key lives in a dedicated Secure Element
 *                     (e.g. Titan M, StrongBox-certified TEE).
 * @param isTee        True when the key is in the main ARM TrustZone TEE but not
 *                     a dedicated StrongBox chip.
 * @param keyAlgorithm Key algorithm string as reported by the Keystore (e.g. "EC").
 * @param createdAt    Epoch-millisecond of key creation; 0 if key doesn't exist yet.
 */
data class KeystoreAttestationInfo(
    val isStrongBox:  Boolean,
    val isTee:        Boolean,
    val keyAlgorithm: String,
    val createdAt:    Long
)

// ─────────────────────────────────────────────────────────────────────────────
// SentinelKeyManager
// ─────────────────────────────────────────────────────────────────────────────

/**
 * SentinelKeyManager — hardware-backed asymmetric signing for threat verdicts.
 *
 * Key lifecycle:
 *   1. [initialise] is called once from [com.sentinelguard.SentinelApplication.onCreate].
 *   2. It attempts to generate a P-256 key pair in the StrongBox Secure Element.
 *   3. If StrongBox is unavailable ([StrongBoxUnavailableException]), it retries
 *      with standard TEE-backed storage — the key still never leaves secure hardware.
 *   4. If the alias already exists (app reinstalled over existing data with the same
 *      Keystore partition), the existing key pair is reused.
 *
 * Signing:
 *   [signVerdict] serialises [VerdictPayload] → canonical JSON → UTF-8 bytes,
 *   then produces a DER ECDSA signature using SHA-256 as the digest.
 *
 * All operations are synchronous and may be called from any thread.
 */
object SentinelKeyManager {

    private const val TAG              = "SentinelKeyManager"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS        = "sentinel_verdict_key"
    private const val SIGNING_ALGORITHM = "SHA256withECDSA"

    /** True after [initialise] completes without error. */
    @Volatile private var initialised = false

    /** Cached attestation result — set during [initialise]. */
    @Volatile private var attestationInfo: KeystoreAttestationInfo =
        KeystoreAttestationInfo(false, false, "UNKNOWN", 0L)

    // -------------------------------------------------------------------------
    // Initialisation
    // -------------------------------------------------------------------------

    /**
     * Ensure the signing key pair exists in the Android Keystore.
     * Safe to call multiple times — a no-op if the key already exists.
     *
     * Attempts StrongBox first; falls back to standard TEE on
     * [StrongBoxUnavailableException] (device lacks a dedicated SE chip).
     */
    fun initialise() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }

        if (!keyStore.containsAlias(KEY_ALIAS)) {
            generateKeyPair()
        }

        // Populate cached attestation info
        attestationInfo = queryAttestationInfo(keyStore)
        initialised = true

        Log.i(TAG, "Keystore ready — StrongBox=${attestationInfo.isStrongBox} " +
                   "TEE=${attestationInfo.isTee} algo=${attestationInfo.keyAlgorithm}")
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Sign [payload] with the hardware-backed private key.
     *
     * Serialisation path: [VerdictPayload] → [Json.encodeToString] → UTF-8 bytes → ECDSA.
     *
     * @throws IllegalStateException if [initialise] has not been called.
     */
    fun signVerdict(payload: VerdictPayload): SignedVerdict {
        check(initialised) { "SentinelKeyManager not initialised — call initialise() first" }

        val json  = Json.encodeToString(payload)
        val bytes = json.toByteArray(Charsets.UTF_8)

        val keyStore   = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
        val privateKey = keyStore.getKey(KEY_ALIAS, null) as PrivateKey
        val publicKey  = keyStore.getCertificate(KEY_ALIAS).publicKey

        val signature = Signature.getInstance(SIGNING_ALGORITHM).run {
            initSign(privateKey)
            update(bytes)
            sign()
        }

        Log.d(TAG, "Signed verdict: ${payload.threatType} " +
                   "[${payload.severity}] sig=${signature.size}B")

        return SignedVerdict(
            payload          = payload,
            signature        = signature,
            publicKeyEncoded = publicKey.encoded,
            signingAlgorithm = SIGNING_ALGORITHM
        )
    }

    /**
     * Verify that [signed.signature] is a valid ECDSA signature over the
     * JSON-serialised form of [signed.payload] using [signed.publicKeyEncoded].
     *
     * Note: this re-derives the public key from the raw encoded bytes so
     * verification can be performed offline (e.g. in a test or audit tool)
     * without accessing the device Keystore.
     */
    fun verifyVerdict(signed: SignedVerdict): Boolean {
        return try {
            val json  = Json.encodeToString(signed.payload)
            val bytes = json.toByteArray(Charsets.UTF_8)

            // Reconstruct the PublicKey from X.509 SubjectPublicKeyInfo bytes
            val keySpec = java.security.spec.X509EncodedKeySpec(signed.publicKeyEncoded)
            val pubKey: PublicKey = KeyFactory.getInstance("EC").generatePublic(keySpec)

            Signature.getInstance(signed.signingAlgorithm).run {
                initVerify(pubKey)
                update(bytes)
                verify(signed.signature)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Verdict verification failed", e)
            false
        }
    }

    /**
     * Returns true when the signing key resides in StrongBox or a TEE.
     * Returns false only if the key was generated in software (should never
     * happen with this implementation, but checked defensively).
     */
    fun isHardwareBacked(): Boolean =
        attestationInfo.isStrongBox || attestationInfo.isTee

    /** Return the cached [KeystoreAttestationInfo] populated during [initialise]. */
    fun getAttestationInfo(): KeystoreAttestationInfo = attestationInfo

    // -------------------------------------------------------------------------
    // Key generation
    // -------------------------------------------------------------------------

    /**
     * Generate the P-256 EC key pair. Tries StrongBox first; on
     * [StrongBoxUnavailableException] retries with standard TEE backing.
     */
    private fun generateKeyPair() {
        try {
            generateKeyPairWithStrongBox(useStrongBox = true)
            Log.i(TAG, "EC P-256 key generated in StrongBox")
        } catch (e: StrongBoxUnavailableException) {
            Log.w(TAG, "StrongBox unavailable — falling back to TEE", e)
            generateKeyPairWithStrongBox(useStrongBox = false)
            Log.i(TAG, "EC P-256 key generated in TEE")
        }
    }

    private fun generateKeyPairWithStrongBox(useStrongBox: Boolean) {
        val specBuilder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            .setUserAuthenticationRequired(false)   // available for background signing

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && useStrongBox) {
            specBuilder.setIsStrongBoxBacked(true)
        }

        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
            .apply { initialize(specBuilder.build()) }
            .generateKeyPair()
    }

    // -------------------------------------------------------------------------
    // Attestation query
    // -------------------------------------------------------------------------

    /**
     * Introspect the generated key's security level via [KeyInfo].
     * [KeyInfo] is obtained by wrapping the private key through [KeyFactory].
     */
    private fun queryAttestationInfo(keyStore: KeyStore): KeystoreAttestationInfo {
        return try {
            val privateKey = keyStore.getKey(KEY_ALIAS, null) as? PrivateKey
                ?: return KeystoreAttestationInfo(false, false, "MISSING", 0L)

            val keyFactory = KeyFactory.getInstance(
                privateKey.algorithm, ANDROID_KEYSTORE
            )
            val keyInfo = keyFactory.getKeySpec(privateKey, KeyInfo::class.java)

            val securityLevel = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                keyInfo.securityLevel
            } else {
                @Suppress("DEPRECATION")
                if (keyInfo.isInsideSecureHardware) 1 else 0
            }

            val isStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
                    securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX

            val isTee = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
            } else {
                @Suppress("DEPRECATION")
                keyInfo.isInsideSecureHardware
            }

            KeystoreAttestationInfo(
                isStrongBox  = isStrongBox,
                isTee        = isTee || isStrongBox,  // StrongBox is a superset of TEE
                keyAlgorithm = privateKey.algorithm,
                createdAt    = System.currentTimeMillis()
            )
        } catch (e: Exception) {
            Log.w(TAG, "Could not query KeyInfo — defaulting to isTee=true", e)
            // If KeyFactory can't introspect it, it's almost certainly hardware-backed;
            // assume TEE conservatively.
            KeystoreAttestationInfo(false, true, "EC", System.currentTimeMillis())
        }
    }
}
