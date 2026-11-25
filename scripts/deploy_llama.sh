#!/usr/bin/env bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# deploy_llama.sh — Push Llama 3.2 1B model to an Android device for SentinelGuard
#
# Usage:
#   chmod +x scripts/deploy_llama.sh
#   ./scripts/deploy_llama.sh [MODEL_PTE] [TOKENIZER_BIN]
#
# Defaults:
#   MODEL_PTE    = llama3_2_1b_xnnpack_q8.pte   (look in current directory)
#   TOKENIZER    = tokenizer.bin
#
# How to get the model files:
#   See scripts/export_llama.md for the full ExecuTorch export walkthrough.
#   Quick path using pre-quantized checkpoint:
#     pip install executorch
#     python -m executorch.examples.models.llama.export_llama \
#       --checkpoint llama3_2_1b_instruct.pth \
#       --params params.json \
#       --xnnpack --quantize 8da4w \
#       --output_name llama3_2_1b_xnnpack_q8.pte
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

set -euo pipefail

# ── Configurable ──────────────────────────────────────────────────────────────
MODEL_PTE="${1:-llama3_2_1b_xnnpack_q8.pte}"
TOKENIZER="${2:-tokenizer.bin}"

# Package name — use debug suffix if deploying debug build
PACKAGE="com.sentinelguard.debug"
# For release builds:
# PACKAGE="com.sentinelguard"

DEVICE_DIR="/data/data/${PACKAGE}/files/llama"

# ── Checks ────────────────────────────────────────────────────────────────────
if ! command -v adb &>/dev/null; then
  echo "ERROR: adb not found. Add Android SDK platform-tools to your PATH."
  echo "  export PATH=\$PATH:\$ANDROID_HOME/platform-tools"
  exit 1
fi

if ! adb get-state &>/dev/null; then
  echo "ERROR: No device connected. Enable USB debugging and connect your device."
  exit 1
fi

if [[ ! -f "$MODEL_PTE" ]]; then
  echo "ERROR: Model file not found: $MODEL_PTE"
  echo "  Run scripts/export_llama.md steps to generate it."
  exit 1
fi

if [[ ! -f "$TOKENIZER" ]]; then
  echo "ERROR: Tokenizer file not found: $TOKENIZER"
  echo "  Download from: https://huggingface.co/meta-llama/Llama-3.2-1B-Instruct"
  exit 1
fi

# ── Deploy ────────────────────────────────────────────────────────────────────
MODEL_SIZE=$(du -sh "$MODEL_PTE" | cut -f1)
TOK_SIZE=$(du -sh "$TOKENIZER" | cut -f1)

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  SentinelGuard — Llama 3.2 1B Deployment"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Device:    $(adb shell getprop ro.product.model 2>/dev/null | tr -d '\r')"
echo "  Package:   $PACKAGE"
echo "  Model:     $MODEL_PTE  ($MODEL_SIZE)"
echo "  Tokenizer: $TOKENIZER  ($TOK_SIZE)"
echo "  Target:    $DEVICE_DIR"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Make sure the app is installed first
if ! adb shell pm list packages | grep -q "$PACKAGE"; then
  echo "ERROR: Package $PACKAGE not found on device."
  echo "  Install the debug APK first:"
  echo "    adb install app/build/outputs/apk/debug/app-debug.apk"
  exit 1
fi

echo "→ Creating target directory..."
adb shell "run-as $PACKAGE mkdir -p $DEVICE_DIR" 2>/dev/null || \
  adb shell "mkdir -p $DEVICE_DIR" 2>/dev/null || true

echo "→ Pushing model (this may take several minutes)..."
# Push to /sdcard first (faster), then copy to app private dir
adb push "$MODEL_PTE"  /sdcard/Download/model.pte
adb push "$TOKENIZER"  /sdcard/Download/tokenizer.bin

echo "→ Ensuring app has launched (creates filesDir)..."
adb shell "am start -n $PACKAGE/com.sentinelguard.ui.MainActivity" 2>/dev/null || true
sleep 3

echo "→ Staging in /data/local/tmp and making world-readable..."
adb shell "cp /sdcard/Download/model.pte     /data/local/tmp/model.pte"     2>/dev/null
adb shell "cp /sdcard/Download/tokenizer.bin /data/local/tmp/tokenizer.bin" 2>/dev/null
adb shell "chmod 644 /data/local/tmp/model.pte /data/local/tmp/tokenizer.bin" 2>/dev/null

echo "→ Copying tokenizer to app private dir (via run-as)..."
adb shell "run-as $PACKAGE sh -c 'cat /data/local/tmp/tokenizer.bin > $DEVICE_DIR/tokenizer.bin'"

echo "→ Copying model.pte to app private dir (~2.3 GB, may take 2-3 min)..."
adb shell "run-as $PACKAGE sh -c 'cat /data/local/tmp/model.pte > $DEVICE_DIR/model.pte'"

echo "→ Cleaning up staging files..."
adb shell "rm -f /data/local/tmp/model.pte /data/local/tmp/tokenizer.bin" 2>/dev/null || true
adb shell "rm -f /sdcard/Download/model.pte /sdcard/Download/tokenizer.bin" 2>/dev/null || true

echo "→ Verifying..."
MODEL_ON_DEVICE=$(adb shell "run-as $PACKAGE ls -lh $DEVICE_DIR/model.pte 2>/dev/null" | awk '{print $5}')
TOK_ON_DEVICE=$(adb shell "run-as $PACKAGE ls -lh $DEVICE_DIR/tokenizer.bin 2>/dev/null" | awk '{print $5}')

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✓  model.pte      $MODEL_ON_DEVICE on device"
echo "  ✓  tokenizer.bin  $TOK_ON_DEVICE on device"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Restart SentinelGuard on the device."
echo "  → System Status: 'Llama Explainer' dot turns GREEN"
echo "  → Threat Log: 'Explain with AI' button appears on all threat rows"
echo ""
