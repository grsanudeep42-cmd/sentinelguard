package com.sentinelguard.ml

/**
 * Process-scoped singleton reference to the active [LlamaExplainer].
 *
 * Set once by [com.sentinelguard.SentinelApplication] on startup.
 * Construction is cheap — [LlamaExplainer] only checks file existence at
 * initialisation time.
 *
 * The underlying [org.pytorch.executorch.extension.llm.LlmModule] is loaded once on the
 * first [LlamaExplainer.explain] call and **cached for the application
 * lifetime** (singleton pattern inside [LlamaExplainer]). Subsequent calls
 * reuse the loaded module, eliminating the 3–10 s model reload overhead
 * that would otherwise occur per explanation request.
 */
object LlamaExplainerHolder {
    @Volatile
    var explainer: LlamaExplainer? = null
}
