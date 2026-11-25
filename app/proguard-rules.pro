# Add project specific ProGuard rules here.

# ── SentinelGuard core ──────────────────────────────────────────────────────
-keep class com.sentinelguard.vpn.** { *; }
-keep class com.sentinelguard.dns.** { *; }
-keep class com.sentinelguard.sms.** { *; }
-keep class com.sentinelguard.ml.** { *; }
-keep class com.sentinelguard.keystore.** { *; }

# ── Room ─────────────────────────────────────────────────────────────────────
-keep class * extends androidx.room.RoomDatabase
-keep @androidx.room.Entity class *
-keepclassmembers @androidx.room.Entity class * { *; }

# ── Coroutines ───────────────────────────────────────────────────────────────
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}

# ── TensorFlow Lite ──────────────────────────────────────────────────────────
-keep class org.tensorflow.lite.** { *; }
-keepclassmembers class org.tensorflow.lite.** { *; }
-dontwarn org.tensorflow.lite.**

# ── ExecuTorch (Llama 3.2 1B) ───────────────────────────────────────────────
-keep class org.pytorch.executorch.** { *; }
-keepclassmembers class org.pytorch.executorch.** { *; }
-dontwarn org.pytorch.executorch.**
# Keep JNI entry points used by ExecuTorch native libs
-keepclasseswithmembernames class * {
    native <methods>;
}
