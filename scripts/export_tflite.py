#!/usr/bin/env python3
"""
Export MobileBERT threat classifier to TFLite (INT8-quantized).

This script fine-tunes a MobileBERT model on a combined SMS-spam /
PhishTank / malware-URL dataset and exports it to the app's assets folder
so it can be loaded at runtime by ThreatClassifier via BertNLClassifier.

────────────────────────────────────────────────────────────────────────────────
Requirements
────────────────────────────────────────────────────────────────────────────────
    pip install tflite-model-maker pandas scikit-learn

Tested with:
    tflite-model-maker == 0.4.4
    tensorflow          == 2.9.*
    Python              >= 3.8

────────────────────────────────────────────────────────────────────────────────
Dataset
────────────────────────────────────────────────────────────────────────────────
Place a CSV at  scripts/data/threat_dataset.csv  with two columns:
    text   —  raw message text, URL, or domain name
    label  —  one of: Benign | Phishing | Smishing | Malware | CnC

Label names MUST match the ThreatLabel enum in ThreatClassifier.kt exactly
(case-insensitive matching is applied at inference time).

Recommended minimum class sizes:
    Benign    5 000 rows   (balanced general web / SMS traffic)
    Phishing  2 000 rows   (PhishTank verified URLs)
    Smishing  2 000 rows   (SMS spam datasets)
    Malware   1 000 rows   (malware domain / URL lists)
    CnC         500 rows   (command-and-control domain feeds)

────────────────────────────────────────────────────────────────────────────────
Usage
────────────────────────────────────────────────────────────────────────────────
    # From SentinelGuard project root:
    python3 scripts/export_tflite.py

    # Optional flags:
    python3 scripts/export_tflite.py --epochs 10 --batch-size 16

Output:
    app/src/main/assets/threat_classifier.tflite   (~25 MB INT8-quantized)

────────────────────────────────────────────────────────────────────────────────
"""

import argparse
import os
import sys

# ── Argument parsing ──────────────────────────────────────────────────────────

parser = argparse.ArgumentParser(description="Export MobileBERT threat classifier to TFLite")
parser.add_argument("--epochs",     type=int, default=5,  help="Training epochs (default: 5)")
parser.add_argument("--batch-size", type=int, default=32, help="Batch size (default: 32)")
parser.add_argument("--train-split",type=float, default=0.9, help="Train/test split ratio (default: 0.9)")
args = parser.parse_args()

# ── Paths ─────────────────────────────────────────────────────────────────────

SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DATASET_CSV  = os.path.join(SCRIPT_DIR,   "data", "threat_dataset.csv")
ASSETS_DIR   = os.path.join(PROJECT_ROOT, "app", "src", "main", "assets")
OUTPUT_NAME  = "threat_classifier.tflite"
OUTPUT_PATH  = os.path.join(ASSETS_DIR, OUTPUT_NAME)

# Validate dataset exists before importing heavy libs
if not os.path.isfile(DATASET_CSV):
    print(f"ERROR: Dataset not found at {DATASET_CSV}", file=sys.stderr)
    print("See docstring at the top of this script for dataset format.", file=sys.stderr)
    sys.exit(1)

os.makedirs(ASSETS_DIR, exist_ok=True)

# ── Imports (after validation so errors are fast) ─────────────────────────────

print("Importing TFLite Model Maker…")
try:
    from tflite_model_maker import model_spec, text_classifier
    from tflite_model_maker.config import ExportFormat
except ImportError as e:
    print(f"ERROR: {e}", file=sys.stderr)
    print("Install via:  pip install tflite-model-maker pandas", file=sys.stderr)
    sys.exit(1)

# ── Load dataset ──────────────────────────────────────────────────────────────

print(f"Loading dataset: {DATASET_CSV}")
data = text_classifier.DataLoader.from_csv(
    filename     = DATASET_CSV,
    text_column  = "text",
    label_column = "label",
    model_spec   = model_spec.get("mobilebert_classifier"),
    delimiter    = ",",
    shuffle      = True
)

train_data, test_data = data.split(args.train_split)
print(f"  Train: {len(train_data)} rows | Test: {len(test_data)} rows")

# ── Fine-tune ─────────────────────────────────────────────────────────────────

print(f"\nFine-tuning MobileBERT for {args.epochs} epochs…")
spec  = model_spec.get("mobilebert_classifier")
model = text_classifier.create(
    train_data,
    model_spec = spec,
    epochs     = args.epochs,
    batch_size = args.batch_size
)

# ── Evaluate ──────────────────────────────────────────────────────────────────

print("\nEvaluating on test split…")
loss, acc = model.evaluate(test_data)
print(f"  Loss: {loss:.4f}  |  Accuracy: {acc:.4f} ({acc * 100:.1f}%)")

# ── Export ────────────────────────────────────────────────────────────────────

print(f"\nExporting INT8-quantized TFLite model → {OUTPUT_PATH}")
model.export(
    export_dir       = ASSETS_DIR,
    export_format    = ExportFormat.TFLITE,
    tflite_filename  = OUTPUT_NAME
)

size_mb = os.path.getsize(OUTPUT_PATH) / (1024 * 1024)
print(f"\n✓ Done — {OUTPUT_NAME}  ({size_mb:.1f} MB)")
print(f"  Place it in:  app/src/main/assets/{OUTPUT_NAME}")
print(f"  Then rebuild the APK to bundle it.")
