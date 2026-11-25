package com.sentinelguard.ml

import android.content.Context
import android.util.Log
import org.tensorflow.lite.Interpreter
import java.io.BufferedReader
import java.io.FileInputStream
import java.io.InputStreamReader
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel

// ─────────────────────────────────────────────────────────────────────────────
// ThreatClassifier — on-device threat text classifier (TFLite + custom vocab)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Lightweight on-device text classifier for threat detection.
 *
 * Uses a word-embedding + Conv1D model trained by `scripts/train_classifier.py`
 * and exported as:
 *   - `assets/threat_classifier.tflite`  — the TFLite model
 *   - `assets/threat_vocab.txt`           — whitespace-separated vocab (one token per line)
 *
 * The classifier handles its own tokenisation: whitespace split → vocab lookup →
 * int32 token-ID sequence → padded to [MAX_SEQ_LEN] → model inference.
 * This avoids any dependency on TFLite Task Library's BertNLClassifier and its
 * mandatory WordPiece metadata, letting us train with standard TensorFlow.
 *
 * **Labels** (output index order, must match training):
 *   0=Benign  1=CnC  2=Malware  3=Phishing  4=Smishing
 *
 * **Graceful degradation**: if either asset is absent or fails to load,
 * [isLoaded] returns false and [classify] always returns `Benign / 0f`.
 *
 * **Thread safety**: each [classify] call allocates its own buffers; the
 * shared [Interpreter] is synchronised on `this`.
 *
 * **Latency**: embedding + Conv1D model on Cortex-A75 ≈ 1–3 ms per call.
 */
class ThreatClassifier(context: Context) {

    private var interpreter: Interpreter? = null
    private var vocab: Map<String, Int>   = emptyMap()

    init {
        try {
            vocab       = loadVocab(context)
            interpreter = Interpreter(loadModelBuffer(context))
            Log.i(TAG, "ThreatClassifier ready — vocab=${vocab.size} tokens")
        } catch (e: Exception) {
            Log.w(TAG, "ThreatClassifier unavailable: ${e.message}. " +
                       "Run scripts/train_classifier.py on Colab to generate model assets.")
        }
    }

    /** True when both the model and vocabulary loaded successfully. */
    val isLoaded: Boolean get() = interpreter != null && vocab.isNotEmpty()

    /**
     * Classify [text] and return the top [ThreatLabel] with its softmax score.
     * Always returns [FALLBACK] when the classifier is unavailable or errors.
     */
    fun classify(text: String): ThreatResult {
        if (!isLoaded) return FALLBACK

        return try {
            val ids     = tokenise(text)
            val input   = Array(1) { ids }                              // [1, MAX_SEQ_LEN]
            val output  = Array(1) { FloatArray(LABEL_ORDER.size) }    // [1, 5]

            synchronized(this) { interpreter!!.run(input, output) }

            val scores = output[0]
            val best   = scores.indices.maxByOrNull { scores[it] } ?: 0
            ThreatResult(label = LABEL_ORDER[best], confidence = scores[best])
        } catch (e: Exception) {
            Log.e(TAG, "Inference failed: ${e.message}")
            FALLBACK
        }
    }

    /** Release the native interpreter. Call when the classifier is no longer needed. */
    fun close() {
        interpreter?.close()
        interpreter = null
        Log.d(TAG, "ThreatClassifier closed")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Tokenisation
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Whitespace-tokenise [text], look up each token in [vocab],
     * and produce a zero-padded / truncated int array of [MAX_SEQ_LEN] elements.
     * Unknown tokens map to index 1 (`<UNK>`).
     */
    private fun tokenise(text: String): IntArray {
        val tokens = text
            .lowercase()
            .take(MAX_INPUT_CHARS)
            .split(SPLIT_REGEX)
            .filter { it.isNotBlank() }

        return IntArray(MAX_SEQ_LEN) { i ->
            if (i < tokens.size) vocab[tokens[i]] ?: UNK_ID else PAD_ID
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Asset loaders
    // ─────────────────────────────────────────────────────────────────────────

    private fun loadModelBuffer(context: Context): ByteBuffer {
        val fd     = context.assets.openFd(MODEL_ASSET)
        val stream = FileInputStream(fd.fileDescriptor)
        val buffer = stream.channel.map(
            FileChannel.MapMode.READ_ONLY, fd.startOffset, fd.declaredLength
        )
        buffer.order(ByteOrder.nativeOrder())
        return buffer
    }

    private fun loadVocab(context: Context): Map<String, Int> {
        val map = mutableMapOf<String, Int>()
        BufferedReader(InputStreamReader(context.assets.open(VOCAB_ASSET))).use { reader ->
            reader.lineSequence().forEachIndexed { idx, token ->
                if (token.isNotBlank()) map[token.trim()] = idx
            }
        }
        return map
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Constants
    // ─────────────────────────────────────────────────────────────────────────

    companion object {
        private const val TAG            = "ThreatClassifier"
        private const val MODEL_ASSET    = "threat_classifier.tflite"
        private const val VOCAB_ASSET    = "threat_vocab.txt"
        private const val MAX_SEQ_LEN    = 100      // must match training sequence length
        private const val MAX_INPUT_CHARS = 500
        private const val PAD_ID         = 0        // <PAD> token
        private const val UNK_ID         = 1        // <UNK> token

        /**
         * Label order **must** match the class index order used during training.
         * The Colab script sorts labels alphabetically before encoding, so:
         *   0=Benign  1=CnC  2=Malware  3=Phishing  4=Smishing
         */
        private val LABEL_ORDER = arrayOf(
            ThreatLabel.Benign,
            ThreatLabel.CnC,
            ThreatLabel.Malware,
            ThreatLabel.Phishing,
            ThreatLabel.Smishing
        )

        private val SPLIT_REGEX = Regex("[\\s.,/:?=&_\\-]+")

        private val FALLBACK = ThreatResult(label = ThreatLabel.Benign, confidence = 0f)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Result types
// ─────────────────────────────────────────────────────────────────────────────

data class ThreatResult(val label: ThreatLabel, val confidence: Float)

enum class ThreatLabel {
    Benign, Phishing, Smishing, Malware, CnC
}
