plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.ksp)
}

android {
    namespace = "com.sentinelguard"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.sentinelguard"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }

        ndk {
            // Limit native libs to arm64 (physical devices) and x86_64 (emulator).
            // Avoids shipping armeabi-v7a ExecuTorch/TFLite libs that bloat the APK.
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            isMinifyEnabled = false
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }

    // TFLite models must NOT be compressed — the runtime memory-maps them directly.
    // AGP 4.1+ adds .tflite automatically; this is an explicit safety net.
    androidResources {
        noCompress += listOf("tflite", "ptl", "pte")
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Build-time blocklist download
// Downloads the StevenBlack unified hosts list once per build, skipping the
// download if the asset already exists (to keep incremental builds fast).
// The bundled file is used on first launch before the daily WorkManager job runs.
// ─────────────────────────────────────────────────────────────────────────────

val downloadBlocklist by tasks.registering {
    val destFile = file("src/main/assets/blocklist.txt")
    val url      = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"

    description = "Downloads the StevenBlack hosts blocklist into app assets."
    group       = "sentinel"

    outputs.file(destFile)

    doLast {
        if (!destFile.exists() || destFile.length() == 0L) {
            logger.lifecycle("Downloading blocklist → ${destFile.absolutePath}")
            destFile.parentFile.mkdirs()
            @Suppress("DEPRECATION")
            ant.invokeMethod("get", mapOf("src" to url, "dest" to destFile))
            logger.lifecycle("Blocklist downloaded: ${destFile.length() / 1024} KB")
        } else {
            logger.lifecycle("Blocklist already present (${destFile.length() / 1024} KB) — skipping download.")
        }
    }
}

// Wire download task to run before every mergeAssets variant task
afterEvaluate {
    tasks.matching { it.name.startsWith("merge") && it.name.endsWith("Assets") }
         .configureEach { dependsOn(downloadBlocklist) }
}

dependencies {
    // AndroidX Core
    implementation(libs.androidx.core.ktx)

    // Lifecycle
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)

    // Activity + Compose
    implementation(libs.androidx.activity.compose)

    // Compose BOM
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.material.icons.extended)
    debugImplementation(libs.androidx.ui.tooling)

    // Compose Navigation
    implementation(libs.androidx.navigation.compose)

    // Coroutines
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.coroutines.core)

    // Room
    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    ksp(libs.androidx.room.compiler)

    // WorkManager
    implementation(libs.androidx.work.runtime.ktx)

    // Kotlinx Serialization
    implementation(libs.kotlinx.serialization.json)

    // ── ML ───────────────────────────────────────────────────────────────────

    // TFLite core interpreter — runs our custom Conv1D threat classifier
    implementation(libs.tensorflow.lite)
    implementation(libs.tensorflow.lite.support)

    // ExecuTorch — Llama 3.2 1B Instruct on-device inference (XNNPACK backend)
    implementation(libs.executorch.android)

    // ── Testing ──────────────────────────────────────────────────────────────
    testImplementation(libs.junit)
}
