# SentinelGuard 🛡️

> **On-device AI threat detection for Android — no cloud, no compromise.**

[![Bharat AI-SoC Challenge](https://img.shields.io/badge/Bharat%20AI--SoC-PS3%20Cybersecurity-blue)](https://armbharatchallenge.com)
[![Llama](https://img.shields.io/badge/Llama-3.2%201B-purple)](https://huggingface.co/meta-llama/Llama-3.2-1B-Instruct)
[![ExecuTorch](https://img.shields.io/badge/ExecuTorch-1.5.1-orange)](https://github.com/pytorch/executorch)
[![TFLite](https://img.shields.io/badge/TFLite-2.16.1-green)](https://tensorflow.org/lite)
[![Android](https://img.shields.io/badge/Android-API%2026%2B-lightgreen)](https://developer.android.com)

---

## What is SentinelGuard?

SentinelGuard is a fully on-device Android security application that detects and explains cyber threats in real time. It runs a **VPN layer**, a **TFLite Conv1D classifier**, and a **Llama 3.2 1B Instruct** model (via ExecuTorch with the XNNPACK backend) — all locally on the device SoC.

**Zero data leaves the device. Ever.**

Built for **Problem Statement 3** of the [Bharat AI-SoC Challenge 2026-27](https://armbharatchallenge.com): *On-Device Threat, Phishing & Scam Detection*.

---

## Features

| Feature | Technology |
|---------|-----------|
| 🌐 **VPN Traffic Inspection** | Android `VpnService` TUN interface |
| 🔍 **DNS-layer Blocking** | 82,923-domain blocklist (OISD + StevenBlack) |
| 🕵️ **HTTPS SNI Inspection** | TLS ClientHello parsing — no decryption needed |
| 🚫 **QUIC Blocking** | UDP 443 dropped → forces HTTP/2 for full inspection |
| 📡 **Connection Analysis** | Port heuristics, CnC pattern detection |
| 📱 **SMS Phishing Detection** | `SmsReceiver` + Conv1D classifier |
| 🤖 **ML Threat Classification** | TFLite Conv1D · 580 KB · 95% accuracy · 5 classes |
| 💬 **AI Threat Explanation** | Llama 3.2 1B Instruct via ExecuTorch (XNNPACK) |
| 🔐 **Hardware-Signed Verdicts** | Android Keystore (StrongBox/TEE) ECDSA P-256 |
| 🛠️ **Remediation Advice** | Urgency-colour-coded action cards |
| 📊 **Live Dashboard** | Compose UI · animated shield · real-time events |

---

## Architecture

```
VPN Service ──▶ DNS Inspector ──▶ Blocklist (82K domains)
     │               │
     │               └──▶ SNI Inspector (TCP 443, plaintext hostname)
     │
     ▼ QUIC Block (UDP 443 dropped → forces HTTP/2)
Connection Analyser ──▶ Port/IP heuristics
     │
     ▼
SMS/Notification Listener ──▶ ScamDetector
     │
     ▼
ML Classifier (TFLite Conv1D) ──▶ 5-class threat label + confidence
     │
     ▼
Llama Explainer (ExecuTorch + XNNPACK) ──▶ Streamed natural-language explanation
     │
     ▼
Hardware Keystore ──▶ ECDSA-signed verdict stored in Room DB
     │
     ▼
Compose UI ──▶ Dashboard · Threat Log · System Status
```

---

## ML Models

### Threat Classifier (TFLite)
- **Architecture**: Embedding(8000, 64) → Conv1D(128, 5) → Conv1D(64, 3) → GlobalMaxPooling1D → Dense(64) → Dense(5, softmax)
- **Size**: 580 KB (dynamic range quantised)
- **Accuracy**: 95% validation accuracy
- **Classes**: `Benign` · `CnC` · `Malware` · `Phishing` · `Smishing`
- **Training data**: 13,992 samples (UCI SMS Spam + pirocheto/phishing-url + synthetic)
- **Training script**: [`scripts/train_classifier.py`](scripts/train_classifier.py) (Google Colab ready)

### Llama Explainer (ExecuTorch)
- **Model**: Llama 3.2 1B Instruct (Meta)
- **Format**: `.pte` (ExecuTorch portable format)
- **Runtime**: `org.pytorch:executorch-android:1.5.1` with XNNPACK delegate
- **Backend**: XNNPACK — leverages Arm NEON SIMD on arm64-v8a
- **Latency**: ~3–8s first token, ~6–12 tok/s streaming
- **Size**: ~700 MB on-device (8da4w quantised)

---

## Quickstart

### 1. Build

```bash
export ANDROID_HOME=~/Android/Sdk
git clone https://github.com/grsanudeep42-cmd/sentinelguard && cd sentinelguard
./gradlew assembleDebug
# APK → app/build/outputs/apk/debug/app-debug.apk
```

### 2. Install
```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

### 3. Deploy Llama Model (for AI explanations)

Export the Llama 3.2 1B model to ExecuTorch `.pte` format — see [`scripts/export_llama.md`](scripts/export_llama.md) for the full walkthrough. Quick path:

```bash
# Export (requires Meta licence acceptance + ExecuTorch SDK)
python -m executorch.examples.models.llama.export_llama \
  --checkpoint ./llama3_2_1b/original/consolidated.00.pth \
  --params ./llama3_2_1b/original/params.json \
  --xnnpack --quantize 8da4w \
  --output_name llama3_2_1b_xnnpack_q8.pte
```

Then push to device:
```bash
chmod +x scripts/deploy_llama.sh
./scripts/deploy_llama.sh llama3_2_1b_xnnpack_q8.pte tokenizer.bin
```

The app will show **Llama Explainer: ✅ Ready** in System Status once both model files are present.

### 4. Grant Permissions (on device)
- **VPN permission** — dialog appears on first VPN toggle in dashboard
- **SMS permission** — grant when prompted
- **Notification Listener** — Settings → Special App Access → Notification Access → SentinelGuard

---

## Project Structure

```
SentinelGuard/
├── app/src/main/java/com/sentinelguard/
│   ├── ml/
│   │   ├── ThreatClassifier.kt      # TFLite Conv1D inference engine
│   │   └── LlamaExplainer.kt        # ExecuTorch LlmModule wrapper (Llama 3.2 1B)
│   ├── vpn/
│   │   ├── SentinelVpnService.kt    # Android VpnService + TUN
│   │   ├── ConnectionAnalyser.kt    # Port/IP heuristics
│   │   └── BootReceiver.kt          # Auto-start on boot
│   ├── dns/
│   │   ├── DnsInspector.kt          # DNS query interception + blocking
│   │   ├── BlocklistUpdater.kt      # WorkManager daily refresh
│   │   └── BlockedDomain.kt         # Room entity
│   ├── sms/
│   │   ├── SmsReceiver.kt           # SMS BroadcastReceiver
│   │   ├── SentinelNotificationListenerService.kt
│   │   └── ScamDetector.kt          # Regex pre-filter + ML enrichment
│   ├── keystore/
│   │   ├── SentinelKeyManager.kt    # Android Keystore ECDSA
│   │   ├── VerdictExporter.kt       # JSON audit log exporter
│   │   └── VerdictLogger.kt         # Room DB signed verdicts
│   ├── ui/
│   │   ├── screens/
│   │   │   ├── DashboardScreen.kt
│   │   │   ├── ExplanationBottomSheet.kt
│   │   │   ├── ThreatLogScreen.kt
│   │   │   └── SystemStatusScreen.kt
│   │   ├── RemediationAdvice.kt
│   │   ├── MainViewModel.kt
│   │   └── MainActivity.kt
│   └── SentinelApplication.kt       # Application singleton + init chain
├── app/src/main/assets/
│   ├── threat_classifier.tflite     # 580 KB Conv1D model
│   ├── threat_vocab.txt             # 8,000 token vocabulary
│   └── blocklist.txt                # 82,923 domains (StevenBlack + OISD)
├── scripts/
│   ├── train_classifier.py          # Colab training script
│   ├── deploy_llama.sh              # adb push helper (Llama 3.2 1B)
│   └── export_llama.md              # ExecuTorch export walkthrough
└── docs/
    └── technical_report.md          # Full technical report
```

---

## Demo

> 📹 **[Demo Video](#)** *(link to be added after recording)*

Demo flow:
1. App launch → Dashboard (animated shield, INACTIVE)
2. Toggle VPN → shield pulses, PROTECTED, DNS Inspector goes green
3. Trigger test threat (blocked domain in browser) → threat card appears with ML label badge
4. Open Threat Log → expand row → Hardware Verified chip + RECOMMENDED ACTION → tap "Explain with AI" → Llama streams explanation
5. System Status → all 7 dots green

---

## Technical Report

📄 [Full Technical Report](docs/technical_report.md)

---

## Challenge Details

| Item | Value |
|------|-------|
| Challenge | Bharat AI-SoC Challenge 2026-27 (2nd Edition) |
| Organiser | Arm + MeitY C2S + IIT Delhi |
| Problem Statement | PS3 — Cybersecurity & Digital Safety |
| Theme | Applied AI on SoC |
| Phase 1 Deadline | 25 November 2026 |
| Phase 2 Deadline | 5 February 2027 |

---

## Required Technologies

| Technology | Usage | Status |
|-----------|-------|--------|
| **Llama 3.2 1B Instruct** | Advisory / reasoning LLM for threat explanation | ✅ Deployed via ExecuTorch |
| **ExecuTorch 1.5.1** | On-device Llama inference runtime (XNNPACK backend) | ✅ arm64-v8a + NEON SIMD |

---

## Licence

This project is submitted for the Bharat AI-SoC Challenge. Llama 3.2 is used under the [Llama 3.2 Community Licence](https://huggingface.co/meta-llama/Llama-3.2-1B). All other code is original.
