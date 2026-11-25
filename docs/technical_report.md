# SentinelGuard — Final Technical Report
### Bharat AI-SoC Challenge 2026-27 | Problem Statement 3
**On-Device Threat, Phishing & Scam Detection**

- **Team:** SentinelGuard (Anudeep GRS)
- **Theme:** Cybersecurity & Digital Safety — Applied AI on SoC
- **Repository:** `https://github.com/grsanudeep42-cmd/sentinelguard`
- **Target Hardware:** Arm64 Android Smartphones (`arm64-v8a`), validated on Realme RMX3998 (MediaTek MT6835 — 2× Arm Cortex-A76 + 6× Arm Cortex-A55, 6 GB RAM, Android 16)
- **Required Stack:** Meta Llama 3.2 1B Instruct (`SpinQuant INT4`) via ExecuTorch `1.5.1` (`XNNPACK` delegate)
- **Submission Date:** November 2026

---

## 1. Executive Summary

SentinelGuard is a privacy-preserving, zero-cloud Android security application that monitors network DNS/HTTPS traffic, SMS messages, and app notifications in real time to detect phishing, smishing, Command-and-Control (C2) communication, and malware activity — explaining every threat to non-technical users in plain English directly on the mobile SoC.

All detection, ML classification, LLM reasoning, and cryptographic verdict signing run **100% locally on Arm hardware** with zero network telemetry or cloud inference dependencies:
1. **Network & DNS Protection (`SentinelVpnService`, `DnsInspector`, `ConnectionAnalyser`)** — Split-tunnel IPv4 VPN (`10.0.0.2/32`) with DoH/DoT bypass capture, RFC 791/768 checksummed `NXDOMAIN` sinkholing, 76,105-entry StevenBlack hosts blocklist with parent-domain lookup, abused-TLD suffix trie, Shannon entropy DGA scoring, TLS ClientHello SNI extraction, QUIC (`UDP/443`) suppression, and C2 port/beaconing heuristics.
2. **SMS & Notification Guard (`SmsReceiver`, `SentinelNotificationListenerService`, `ScamDetector`)** — Hybrid 6-signal weighted rule engine (Urgency, Financial, Suspicious Links, OTP Fraud, Brand Impersonation, Grammar/Unicode Lookalike anomalies) fused with on-device TFLite classification.
3. **Edge Threat Classifier (`ThreatClassifier`)** — 576 KB TensorFlow Lite 5-class classifier (`Benign`, `CnC`, `Malware`, `Phishing`, `Smishing`) achieving **99.7% validation accuracy** across 14,232 samples.
4. **On-Device Advisory LLM (`LlamaExplainer`)** — **Meta Llama 3.2 1B Instruct** (`SpinQuant_INT4_EO8`) executed via **ExecuTorch 1.5.1** (`XNNPACK` Arm NEON backend), delivering **21.67 tok/s** prefill (3.14 s time-to-first-token) and **11.54 tok/s** decode on a mid-range MediaTek MT6835 smartphone.
5. **Tamper-Evident Audit Log (`SentinelKeyManager`, `VerdictLogger`, `VerdictExporter`)** — Hardware TEE-backed ECDSA P-256 (`SHA256withECDSA`) verdict signing persisted in Room DB with one-tap JSON audit export.

---

## 2. System Architecture & Methodology

```
┌──────────────────────────────────────────────────────────────────────────┐
│                 Arm64 Android Device (arm64-v8a / MT6835)                │
│                                                                          │
│  ┌─────────────────┐    ┌───────────────────┐    ┌───────────────────┐  │
│  │ SentinelVpnSvc  │───▶│   DnsInspector    │───▶│  HashSet (76.1K)  │  │
│  │ Split-Tunnel IPv4│    │ UDP/53 + TLS SNI  │    │  Suffix Trie (.tk)│  │
│  │ DoH Capture     │    │ RFC791/768 Reply  │    │  DGA Label Entropy│  │
│  └────────┬────────┘    └─────────┬─────────┘    └───────────────────┘  │
│           │                       │                                      │
│           ▼                       ▼                                      │
│  ┌──────────────────────────────────────────┐                           │
│  │           ConnectionAnalyser             │                           │
│  │  Malware Ports · C2 Beaconing (≠ DNS:53) │                           │
│  └────────────────────┬─────────────────────┘                           │
│                       │                                                  │
│  ┌────────────────────▼─────────────────────┐                           │
│  │   SmsReceiver & NotificationListener     │                           │
│  │  ScamDetector (6 signals + Unicode check)│                           │
│  └────────────────────┬─────────────────────┘                           │
│                       │                                                  │
│           ┌───────────▼───────────────┐                                  │
│           │     ThreatClassifier      │  ← TFLite 2.16.1 (Arm XNNPACK)  │
│           │  576 KB · 5-Class · 99.7% │                                  │
│           └───────────┬───────────────┘                                  │
│                       │                                                  │
│           ┌───────────▼───────────────┐                                  │
│           │      LlamaExplainer       │  ← ExecuTorch 1.5.1 (XNNPACK)   │
│           │ Llama 3.2 1B SpinQuant I4 │                                  │
│           └───────────┬───────────────┘                                  │
│                       │                                                  │
│           ┌───────────▼───────────────┐                                  │
│           │  Keystore & VerdictLogger │  ← Arm TrustZone TEE (ECDSA P256)│
│           │  Signed Room DB + JSON    │                                  │
│           └───────────┬───────────────┘                                  │
│                       │                                                  │
│           ┌───────────▼───────────────┐                                  │
│           │    Jetpack Compose UI     │                                  │
│           │ Dashboard·ThreatLog·Status│                                  │
│           └───────────────────────────┘                                  │
└──────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Local VPN & DoH-Resistant DNS Inspection (`SentinelVpnService.kt`, `DnsInspector.kt`)
1. **Virtual TUN Configuration:** Establishes a local IPv4 TUN (`10.0.0.2/32`, MTU `1500`) advertising virtual resolver `10.0.0.1` (`LOCAL_TUN_DNS`) instead of `8.8.8.8`. Using an RFC 1918 resolver IP prevents Chrome/Android from auto-upgrading to encrypted DNS-over-HTTPS (DoH).
2. **Browser DoH/DoT Bypass Capture:** Routes known public DoH/DoT IPs (`8.8.8.8`, `8.8.4.4`, `1.1.1.1`, `1.0.0.1`, `9.9.9.9`, `149.112.112.112`, `94.140.14.14`, `94.140.15.15`, `208.67.222.222`, `208.67.220.220`) into the TUN so browser DoH probes fall back cleanly onto the inspected TUN UDP/53 resolver. SentinelGuard's own sockets are excluded via `builder.addDisallowedApplication(packageName)` and `protect(socket)` to prevent routing loops.
3. **IPv6 Dual-Stack Safety & Upstream Failover:** `ConnectivityManager.LinkProperties.dnsServers` is filtered to `Inet4Address` only (preventing `IllegalArgumentException: Bad address` when passing IPv6 addresses to `/32` IPv4 `addRoute` calls on dual-stack Wi-Fi / 5G carriers), while raw upstream DNS addresses are retained in `fallbackUpstreamDns` for failover and responsive DNS promotion (`8.8.8.8`, `1.1.1.1`).
4. **Three-Layer `DnsInspector` Classification:**
   - **Layer 1 — Exact + Parent-Domain Blocklist:** $O(1)$ `HashSet<String>` seeded with `76,105` host entries from StevenBlack Unified Hosts (`assets/blocklist.txt`, 2.3 MB) plus 20 abuse.ch/OpenPhish seed domains, walking parent labels (e.g., blocking `cdn.iplogger.org` when `iplogger.org` is listed) and kept fresh daily via `BlocklistUpdater` (`WorkManager`).
   - **Layer 2 — Suffix Trie:** Reversed-label trie flagging 20 abused free TLDs (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.pw`, `.top`, `.xyz`, `.icu`, `.work`, `.click`, `.link`, `.online`, `.site`, `.live`, `.stream`, `.download`, `.review`, `.country`, `.kim`).
   - **Layer 3 — Shannon Entropy DGA Detector:** Evaluates $H(X) = -\sum p(x)\log_2 p(x)$ on the longest `.`/`-`-delimited hostname token ($\text{length} \ge 16$, $H > 3.6$ bits/char).
5. **RFC-Compliant Packet Synthesis (`NXDOMAIN` & DNS Replies):** Wraps DNS payloads inside IPv4+UDP packets with full **RFC 791 IPv4 header checksums** and **RFC 768 UDP pseudo-header checksums**, ensuring 0 `IpInHdrErrors` kernel drops.
6. **HTTPS SNI & QUIC Control:** Drops UDP/443 (QUIC) to encourage TCP/TLS fallback and parses TLS ClientHello SNI extensions (RFC 5246/8446) in plaintext without MITM TLS termination.

### 2.2 Connection Behaviour Analyser (`ConnectionAnalyser.kt`)
- Flags outbound traffic to high-risk RAT/C2/Tor ports (`4444`, `5555`, `6666`, `1337`, `31337`, `8080`, `8443`, `9001`, `9030`) as `MALWARE_PORT` (`HIGH`).
- Tracks per-destination IP timestamps in an LRU-bounded `LinkedHashMap` (max 1,000 IPs, 30s sliding window, threshold > 8 hits) to emit `BEACON` (`MEDIUM`), explicitly excluding `dstPort == 53` DNS lookups to prevent false alerts on local DNS resolvers.

### 2.3 SMS & Notification Fraud Pipeline (`SmsReceiver.kt`, `SentinelNotificationListenerService.kt`, `ScamDetector.kt`)
- Intercepts `SMS_RECEIVED` broadcasts and active messaging notifications without persisting raw SMS messages outside confirmed threats.
- Combines 6 weighted heuristic signals (`URGENCY` 0.30, `FINANCIAL` 0.30, `SUSPICIOUS_LINK` 0.25, `IMPERSONATION` 0.25, `OTP_PATTERN` 0.20, `GRAMMAR_ANOMALY` 0.15 including Cyrillic/fullwidth homoglyph confusable detection) with TFLite ML enrichment:
  $$\text{confidence} = \min\Big(\max\big(w_{\text{regex}},\, 1.2 \times p_{\text{ML}}\big),\, 1.0\Big)$$
  Categorises positive detections (`>= 0.45`) into `OTP_FRAUD`, `KYC_SCAM`, `BANK_FRAUD`, `LOTTERY_SCAM`, or `DELIVERY_SCAM`.

### 2.4 Edge ML Classifier (`ThreatClassifier.kt`)
- **Architecture:** `Embedding(8000)` (`embedding_lookup`, `MAX_SEQ_LEN=100`) → Dual `Conv1D + ReLU` (`conv1d` → `Relu_1` → `conv1d_1` → `Relu_2`) → Pooling → `Dense + Softmax` (`5` classes).
- **Dataset:** 14,232 samples combining HuggingFace `ucirvine/sms_spam`, `pirocheto/phishing-url`, and synthetic CnC/Malware patterns across 5 balanced classes: `Benign` (0), `CnC` (1), `Malware` (2), `Phishing` (3), `Smishing` (4), using an 8,000-token whitespace vocabulary (`assets/threat_vocab.txt`).
- **Footprint:** 576 KB (`589,728` bytes) `.tflite` flatbuffer memory-mapped read-only via `FileChannel.MapMode.READ_ONLY`, executed on Arm CPU/NEON with TFLite `2.16.1` (target ~1–3 ms per call on Cortex-A75/A76-class cores).

### 2.5 On-Device Advisory LLM (`LlamaExplainer.kt`)
- **Model:** Meta **Llama 3.2 1B Instruct** (`Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8.pte`, 1.08 GB on disk) + TikToken `tokenizer.bin` (2.0 MB).
- **Runtime:** ExecuTorch Android `1.5.1` (`org.pytorch.executorch.extension.llm.LlmModule`, `LlmModuleConfig`, `LlmGenerationConfig`, `LlmCallback`) using **Arm XNNPACK** NEON delegate.
- **Inference Configuration:** Greedy decoding (`temperature = 0.0f`), `echo(false)`, `warming(false)`, `LOAD_MODE_MMAP`, `seqLen(192)`, `maxNewTokens(110)`, with `resetContext()` called before each alert explanation so consecutive threats stay isolated in the KV-cache.

### 2.6 Hardware-Backed Verdict Attestation (`SentinelKeyManager.kt`, `VerdictLogger.kt`, `VerdictExporter.kt`)
- Generates a non-exportable ECDSA P-256 (`SHA256withECDSA`) key pair in Android Keystore (`StrongBox` preferred with automatic Arm TrustZone **TEE** fallback).
- Every `ThreatEvent` is signed, stored in Room SQLite (`SignedVerdictEntity`), displayed with a **"Hardware Verified"** badge and public key preview, and exportable as signed JSON via MediaStore (`Downloads/SentinelGuard_audit_*.json`).

---

## 3. Experimental Results & Hardware Verification

All tests were executed directly on a physical **Realme RMX3998** smartphone (**MediaTek MT6835**, Android 16, 6 GB RAM) and via Gradle JVM unit tests:

### 3.1 Unit Test Suite (`./gradlew testDebugUnitTest`)
| Suite | Scope | Result | Time |
|---|---|---|---|
| `DnsInspectorTest` | Blocklist, parent-domain (`track.iplogger.org`), `.tk` TLD, high-entropy DGA, multi-label clean hosts (`z-m-gateway.facebook.com`, `sentry-prod.branch.io`, `geomobileservices-pa.googleapis.com`), edge cases | **9/9 PASSED** | 0.045 s |
| `ThreatClassifierTest` | 5-class `ThreatLabel` contract, alphabetical index mapping, `ThreatResult` fallback | **5/5 PASSED** | 0.002 s |
| `ScamDetectorTest` | Prize, KYC, Delivery, OTP fraud, excessive caps, signal extraction, clean greetings, empty inputs | **10/10 PASSED** | 0.012 s |
| **Total** | **All JVM unit tests** | **24 / 24 PASSED (0 failed)** | **0.059 s** |

### 3.2 Live Network, Browser & SMS Verification on Device
| Test Case | Observed Device Result |
|---|---|
| Dual-stack Wi-Fi + 5G DNS startup | `tun0` established (`fd`, `10.0.0.1` virtual DNS) with 0 crashes despite IPv6 DNS (`2405:201:...`) |
| Malicious domain in Chrome (`https://iplogger.org`) | Blocked cleanly (`DNS_PROBE_FINISHED_NXDOMAIN`), `iplogger.org` & `cdn.iplogger.org` signed & persisted in Room DB |
| Benign domain in Chrome (`https://example.org`) & `ping example.com` | Resolved cleanly via protected upstream DNS (`60.1 ms` RTT, **0 new `IpInHdrErrors`**) |
| Live SMS Scam interception | `SMS SCAM [HIGH, 100%]` detected, signed verdict logged, alert notification posted, `SentinelNotificationListenerService` active |
| TFLite Classifier validation | **99.7% validation accuracy** across 14,232 samples (`Benign`, `CnC`, `Malware`, `Phishing`, `Smishing`) |

### 3.3 Live On-Device Llama 3.2 1B Benchmark (`ExplanationBottomSheet`)
Triggered on an `SMS_SCAM [HIGH, 100%]` alert directly on RMX3998 (`MT6835`):
- **Generated Plain-English Output (60 tokens / 309 chars, completed cleanly at EOS):**
  > *"This phone security alert is dangerous because it's a smishing (SMS phishing) attack, which uses the phone's SMS service to trick users into revealing sensitive information. To protect yourself, do not respond to the alert or click on any links, and instead report the incident to your phone service provider."*
- **Measured Latency & Throughput (`LlmCallback.onStats`):**
  - **Prompt Tokens:** `68` | **Generated Tokens:** `60`
  - **Time to First Token (Prefill):** `3.138 s` (**`21.67 tokens/s`**)
  - **Decode Throughput:** `5.199 s` (**`11.54 tokens/s`**)
  - **Total Generation Time:** `8.337 s` (`7.20 tok/s` overall)
  - **Sampling Overhead:** `14 ms` across 128 token steps

---

## 4. Hardware Utilization

| SoC Subsystem (MediaTek MT6835) | Physical Hardware Spec | Role in SentinelGuard | Measured Utilization / Footprint |
|---|---|---|---|
| **Performance Cores** | 2× Arm Cortex-A76 (`0xd0b`, ARMv8-A) | ExecuTorch XNNPACK GEMM/attention kernels, TFLite Conv1D, VPN TUN packet loop | Active user CPU during LLM inference (`21.67 tok/s` prefill, `11.54 tok/s` decode) |
| **Efficiency Cores** | 6× Arm Cortex-A55 (`0xd05`, ARMv8-A) | Background Room DB seeding, `VerdictLogger`, `SmsReceiver`, `NotificationListener` | Low background overhead; asynchronous Room seeding (`76,104` unique domains) on first launch |
| **Memory Subsystem** | 6 GB LPDDR4X (`5,755,844 kB` total) | Memory-mapped `.pte` weights (`LOAD_MODE_MMAP`), 576 KB TFLite arena, 76K `HashSet` | **1,375.1 MiB RSS** with SpinQuant INT4 Llama loaded & generating (zero ZRAM swap thrashing) |
| **Arm TrustZone / TEE** | Android Keystore Hardware HAL | Non-exportable ECDSA P-256 key generation & signing | `StrongBox=false, TEE=true, algo=EC`, `70–72 B` DER signatures per threat verdict |
| **Storage / APK Budget** | UFS / App Private Storage | Bundled TFLite + blocklist in APK; side-loaded `.pte` in `filesDir/llama/` | **49 MB** Debug APK; `threat_classifier.tflite` **576 KB**; `blocklist.txt` **2.3 MB** |

---

## 5. Optimization Techniques & Before/After Engineering Impact

| Optimization | Problem Identified on Real Hardware | Solution Implemented | Measured Improvement |
|---|---|---|---|
| **1. SpinQuant INT4 Quantization (`8da4w` + `8,0` Embed)** | Unquantized FP16/BF16 Llama 3.2 1B (`2.47 GB`) exhausted 6 GB RAM → **1.7 GB ZRAM swap**, `137% sys` CPU thrashing, 127.3 s latency | Switched to `Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8.pte` (`1.08 GB`, INT4 weights + INT8 dynamic activations, `use_sdpa_with_kv_cache=1`) | RSS: **2,619 MiB → 1,375 MiB (−47.5%)**; Total inference: **127.3 s → 8.34 s (15.3× faster)**; Decode: **0.99 → 11.54 tok/s (11.7×)** |
| **2. `LOAD_MODE_MMAP` + `warming(false)` + Prompt Compression** | `MLOCK` forced OS page swapping; `warming(true)` executed an extra warmup pass; 82-token prompt wasted prefill budget | Changed to `LOAD_MODE_MMAP`, disabled redundant `warming(false)`, compressed system/user prompt (`82 → 68` tokens) + `seqLen(192)` + `resetContext()` | Prefill (TTFT): **81.82 s → 3.14 s (26.1× faster)**; clean EOS completion without truncation |
| **3. TFLite TF 2.16.1 Concrete-Function Op-v9 Export** | Keras 3 / TF 2.21 emitted `FULLY_CONNECTED` v12 ops incompatible with Android TFLite `2.16.1` runtime (`LSTM TensorListReserve` issue) | Re-exported with TF `2.16.1` concrete `tf.Module` + `Optimize.DEFAULT` dynamic-range quantization (`576 KB`, zero `SELECT_TF_OPS`) | **99.7% val accuracy** (14,232 samples), Arm CPU memory-mapped execution, **576 KB** APK footprint |
| **4. Split-Tunnel DNS + DoH Bypass Capture + RFC Checksums** | Capturing `0.0.0.0/0` without TCP NAT broke browsing; `8.8.8.8` triggered Chrome DoH (`8.8.4.4:443`) bypass; `pkt[10..11]=0` caused kernel `IpInHdrErrors` drops | Advertised virtual `10.0.0.1` DNS, captured 10 public DoH resolver IPs into TUN, excluded own UID, added RFC 791 IPv4 + RFC 768 UDP checksums | **0 kernel packet errors**, Chrome blocks `iplogger.org` (`NXDOMAIN`) while safe sites load normally |
| **5. False-Positive Reduction (DGA & Beacons)** | Whole-FQDN entropy (`>3.5`) blocked `z-m-gateway.facebook.com`, `sentry-prod.branch.io`, `geomobileservices-pa.googleapis.com`; port 53 triggered `BEACON` on router | Scored entropy on longest `.`/`-` label ($\ge 16$ chars, $> 3.6$), added parent-domain blocklist lookup, excluded UDP/53 from C2 beacon tracking | Zero false positives on tested Google/Facebook/Branch domains; subdomain blocking verified |

---

## 6. Privacy, Security & Build Quickstart

- **Zero Cloud Dependency:** All ML (`threat_classifier.tflite`), LLM (`model.pte` via ExecuTorch), DNS filtering, SMS scanning, and cryptographic signing run strictly on-device.
- **No Raw SMS Persistence:** Incoming SMS bodies are scored ephemerally in RAM; only malicious verdicts are persisted in the encrypted/app-private Room database.

```bash
# Build & Run Tests
export ANDROID_HOME=~/Android/Sdk
./gradlew assembleDebug testDebugUnitTest    # 24/24 unit tests passing, 49 MB APK

# Install & Deploy SpinQuant INT4 Llama Model
adb install -r app/build/outputs/apk/debug/app-debug.apk
chmod +x scripts/deploy_llama.sh
./scripts/deploy_llama.sh llama_models/Llama-3.2-1B-Instruct-SpinQuant_INT4_EO8.pte llama_models/tokenizer_instruct.model
```

---
*SentinelGuard | Bharat AI-SoC Challenge 2026-27 | Problem Statement 3 — Cybersecurity & Digital Safety*
