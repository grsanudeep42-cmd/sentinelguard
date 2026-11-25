package com.sentinelguard.ml

import android.content.Context
import android.util.Log
import com.sentinelguard.vpn.ThreatEvent
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.pytorch.executorch.extension.llm.LlmCallback
import org.pytorch.executorch.extension.llm.LlmGenerationConfig
import org.pytorch.executorch.extension.llm.LlmModule
import org.pytorch.executorch.extension.llm.LlmModuleConfig
import java.io.File

// ─────────────────────────────────────────────────────────────────────────────
// LlamaExplainer — on-device threat explanation via Llama 3.2 1B + ExecuTorch
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generates a human-readable explanation for a [ThreatEvent] using
 * **Llama 3.2 1B Instruct** running locally via the ExecuTorch runtime
 * with the XNNPACK backend (Arm NEON SIMD on arm64-v8a).
 *
 * Push model files to device:
 * ```bash
 * chmod +x scripts/deploy_llama.sh
 * ./scripts/deploy_llama.sh llama_models/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8.pte llama_models/tokenizer.model
 * ```
 *
 * **Performance notes:**
 * - The [LlmModule] is loaded once via `LOAD_MODE_MMAP` (no `mlock`, preventing
 *   memory-pressure ZRAM swap thrashing on 6 GB devices) and cached for the
 *   app lifetime.
 * - [LlmGenerationConfig] sets `echo(false)`, `warming(false)` (avoids a full
 *   dummy warmup pass on first tap), `seqLen(MAX_SEQ_LEN)`, and greedy decoding.
 * - `resetContext()` clears KV-cache before each generation so successive alerts
 *   remain isolated and within the context budget.
 *
 * **[isAvailable]** — true when both `model.pte` and `tokenizer.bin` exist on-device.
 * **[explain]** — streams tokens into [onToken] via ExecuTorch's [LlmCallback].
 */
class LlamaExplainer(context: Context) {

    private val modelDir      = "${context.filesDir}/llama"
    private val modelPath     = "$modelDir/model.pte"
    private val tokenizerPath = "$modelDir/tokenizer.bin"

    // ── Cached ExecuTorch LLM module (load once, reuse) ─────────────────────

    @Volatile private var cachedModule: LlmModule? = null
    private val moduleLock = Any()

    /** True when both model and tokenizer files exist on-device. */
    val isAvailable: Boolean
        get() = File(modelPath).exists() && File(tokenizerPath).exists()

    /**
     * Returns the cached [LlmModule], loading from disk on first call.
     * Thread-safe via double-checked locking.
     */
    private fun getOrLoadModule(): LlmModule {
        cachedModule?.let { return it }
        return synchronized(moduleLock) {
            cachedModule ?: run {
                Log.i(TAG, "Loading LlmModule from $modelPath …")
                val config = LlmModuleConfig.create()
                    .modulePath(modelPath)
                    .tokenizerPath(tokenizerPath)
                    .modelType(LlmModuleConfig.MODEL_TYPE_TEXT)
                    .loadMode(LlmModuleConfig.LOAD_MODE_MMAP)
                    .temperature(TEMPERATURE)
                    .build()
                val module = LlmModule(config)
                module.load()
                Log.i(TAG, "Llama 3.2 1B loaded ✓")
                cachedModule = module
                module
            }
        }
    }

    // ── Generation config (shared across calls) ───────────────────────────────

    private val genConfig = LlmGenerationConfig.create()
        .echo(false)              // suppress prompt echo — only new tokens delivered
        .seqLen(MAX_SEQ_LEN)      // LlmModule.generate(String, config, cb) uses seqLen
        .maxNewTokens(MAX_TOKENS)
        .temperature(TEMPERATURE)
        .warming(false)           // skip redundant warmup pass for faster first token
        .build()

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Generate a 2–3 sentence plain-English explanation for [event].
     *
     * Uses ExecuTorch's [LlmCallback] to stream tokens incrementally to [onToken]
     * on [Dispatchers.IO].
     */
    suspend fun explain(
        event:   ThreatEvent,
        onToken: suspend (String) -> Unit
    ) = withContext(Dispatchers.IO) {

        if (!isAvailable) {
            onToken(MODEL_NOT_FOUND_MSG)
            Log.w(TAG, "Llama model files not found at $modelDir")
            return@withContext
        }

        Log.d(TAG, "Starting Llama explanation for: ${event.type}")

        try {
            val module = getOrLoadModule()
            // Reset KV-cache cleanly before each new alert explanation
            runCatching { module.resetContext() }
            val fullResponse = StringBuilder()

            module.generate(
                buildPrompt(event),
                genConfig,
                object : LlmCallback {
                    override fun onResult(result: String) {
                        val clean = result
                            .replace("<|eot_id|>", "")
                            .replace("<|end_of_text|>", "")
                            .replace("<|end_header_id|>", "")
                            .replace("<|start_header_id|>", "")
                            .replace("<|begin_of_text|>", "")
                        if (clean.isNotEmpty()) {
                            fullResponse.append(clean)
                            kotlinx.coroutines.runBlocking { onToken(clean) }
                        }
                    }

                    override fun onStats(stats: String) {
                        Log.d(TAG, "Llama stats: $stats")
                    }

                    override fun onError(errorCode: Int, message: String) {
                        Log.e(TAG, "Llama error [$errorCode]: $message")
                        kotlinx.coroutines.runBlocking {
                            onToken("\n[Error $errorCode: $message]")
                        }
                    }
                }
            )

            Log.d(TAG, "Llama generation complete: ${fullResponse.length} chars")

        } catch (e: Exception) {
            Log.e(TAG, "Llama generation failed for ${event.type}", e)
            onToken("\n[Explanation generation failed: ${e.message}]")
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Prompt builder — Llama 3.2 Instruct format
    // ─────────────────────────────────────────────────────────────────────────

    private fun buildPrompt(event: ThreatEvent): String {
        val mlCtx      = if (event.mlLabel.isNotBlank()) " (${event.mlLabel})" else ""
        val threatName = event.type.replace('_', ' ')
        return "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n" +
            "Explain why this phone security alert is dangerous and give one action to take in 2 concise sentences (under 45 words). Plain text only.<|eot_id|>" +
            "<|start_header_id|>user<|end_header_id|>\n\n" +
            "$threatName [${event.severity}]$mlCtx: ${event.description.take(120)}<|eot_id|>" +
            "<|start_header_id|>assistant<|end_header_id|>\n\n"
    }

    fun close() {
        synchronized(moduleLock) {
            cachedModule?.close()
            cachedModule = null
        }
        Log.d(TAG, "LlamaExplainer closed")
    }

    companion object {
        private const val TAG         = "LlamaExplainer"
        private const val MAX_SEQ_LEN = 192              // ~50 prompt tok + generous room for complete 2-sentence reply
        private const val MAX_TOKENS  = 110
        private const val TEMPERATURE = 0.0f             // greedy — deterministic + fastest
        private const val MODEL_NOT_FOUND_MSG =
            "[Llama model not installed. Run scripts/deploy_llama.sh to push the model files.]"
    }
}
