# SentinelGuard — Demo Video Script

**Duration**: ~3–4 minutes  
**Setup**: Device connected to laptop via USB, screen mirroring active (e.g., scrcpy or built-in screen record)

---

## Pre-demo Setup Checklist
- [ ] App installed: `adb install -r app-debug.apk` ✅
- [ ] Llama model files pushed via `scripts/deploy_llama.sh`
- [ ] Screen recording started on device
- [ ] VPN permission not yet granted (grant fresh during demo for effect)
- [ ] Device has test SMS / browser available

---

## Scene 1 — App Launch (0:00–0:20)

**Action**: Tap SentinelGuard icon on home screen

**Narration**:
> "This is SentinelGuard — an on-device AI security app built for the Bharat AI-SoC Challenge PS3.  
> Everything you're about to see runs entirely on this phone's SoC. No cloud, no network calls."

**What to show**:
- App launches → Dashboard with animated shield (gray, INACTIVE state)
- Status bar: "PROTECTION OFF"
- System Status dots: VPN ❌, DNS Inspector ❌ (all gray initially)

---

## Scene 2 — Enable Protection (0:20–0:50)

**Action**: Tap the shield / "Enable Protection" button

**What happens**:
- VPN permission dialog appears (Android system dialog)
- Tap "OK"
- Shield animates: pulses with blue glow, turns to PROTECTED state
- Status bar → "PROTECTED"
- System Status: VPN ✅, DNS Inspector ✅, Blocklist (82K domains) ✅

**Narration**:
> "SentinelGuard activates a local VPN tunnel — not a cloud VPN, but a TUN interface on the SoC itself.  
> All traffic passes through our DNS Inspector which checks every query against 82,000 known malicious domains."

---

## Scene 3 — DNS Blocking (0:50–1:20)

**Action**: Open Chrome → type `malware.wicar.org` or any domain from the blocklist

**What happens**:
- Browser shows "This site can't be reached" (NXDOMAIN)
- Immediately: threat card slides into Dashboard  
  - Label: `🔴 Phishing` (or whichever class)
  - Content: the domain name
  - ML confidence badge: e.g., `99% Phishing`
  - Remediation chip: `⚠️ CRITICAL — Do not visit this site`

**Narration**:
> "The DNS Inspector blocked that domain before a single TCP packet was sent.  
> Our TFLite Conv1D classifier — 580 kilobytes, running on-chip — classified it as Phishing with 99% confidence."

---

## Scene 4 — SMS Phishing Detection (1:20–1:50)

**Action**: Send a test SMS to the device:  
`"URGENT: Your SBI account has been blocked. Verify immediately: bit.ly/sbi-verify"`

**What happens**:
- SmsReceiver fires → ScamDetector flags urgency → ThreatClassifier runs
- Notification: "SentinelGuard blocked a Smishing attempt"
- Dashboard: new threat card → `📱 Smishing`, confidence ~68–80%

**Narration**:
> "SMS phishing — smishing — is detected live. The same Conv1D model processes the message in under 5 milliseconds on the Arm Cortex cores."

---

## Scene 5 — Threat Log + AI Explanation (1:50–3:00)

**Action**: Tap "Threat Log" in bottom nav → tap on a threat row to expand it

**What to show**:
- Expanded row: full content, confidence progress bar, `🔐 Hardware Verified` chip
- `RECOMMENDED ACTION` card with specific advice
- Tap **"Explain with AI"** button

**What happens**:
- Bottom sheet opens: "Llama 3.2 1B — Generating explanation…"
- Tokens stream in real-time from Llama 3.2 1B Instruct via ExecuTorch
- Result: 2-sentence explanation + concrete action

**Narration**:
> "Every verdict is signed by an ECDSA P-256 key stored in the hardware security module — tamper-evident, verifiable.  
>   
> When you tap 'Explain with AI', Llama 3.2 — a 1 billion parameter language model by Meta — generates a plain-language explanation in real time.  
> This runs entirely via ExecuTorch with Arm's XNNPACK delegate. Watch the tokens stream."

**Wait for Llama to finish, then:**
> "No network request was made. That entire LLM inference happened on this phone's Arm processor."

---

## Scene 6 — System Status (3:00–3:30)

**Action**: Tap "System Status" in bottom nav

**What to show**:
- 7-row status panel, all green ✅
  - VPN Active
  - DNS Inspector Active  
  - Blocklist: 82,923 domains loaded
  - Connection Analyser Active
  - SMS Listener Active
  - **ML Classifier: Ready** (TFLite · 580 KB · Conv1D)
  - **Llama Explainer: Ready** (ExecuTorch 1.5.1 · XNNPACK)

**Narration**:
> "Seven independent detection layers, all active, all on-device.  
> ML Classifier and Llama Explainer both running on the SoC via Arm's XNNPACK."

---

## Closing (3:30–4:00)

**Action**: Return to Dashboard — shield still pulsing

**Narration**:
> "SentinelGuard demonstrates Applied AI on SoC for Problem Statement 3 of the Bharat AI-SoC Challenge.  
> Privacy-first, edge-first, powered by Arm."

---

## Recording Tips
- Use `adb shell screenrecord /sdcard/sentinel_demo.mp4` or device built-in recorder
- Pull recording: `adb pull /sdcard/sentinel_demo.mp4`
- Target resolution: 1080p, 60fps
- Keep each scene within the time budget — don't rush Llama streaming, it's the showstopper
