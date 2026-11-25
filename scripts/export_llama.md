# Exporting Llama 3.2 1B for SentinelGuard

## What you need

| Item | Source |
|------|--------|
| Llama 3.2 1B Instruct weights | [Meta on HuggingFace](https://huggingface.co/meta-llama/Llama-3.2-1B-Instruct) (requires licence acceptance) |
| ExecuTorch Python SDK | `pip install executorch` |
| `tokenizer.model` → `tokenizer.bin` | Included with weights download |
| ~8 GB RAM + ~16 GB disk | For export |

---

## Step 1 — Accept Meta's licence
Go to [huggingface.co/meta-llama/Llama-3.2-1B-Instruct](https://huggingface.co/meta-llama/Llama-3.2-1B-Instruct) and accept the licence. Then:

```bash
pip install huggingface_hub
huggingface-cli login          # paste your HF token
huggingface-cli download meta-llama/Llama-3.2-1B-Instruct \
  --local-dir ./llama3_2_1b
```

## Step 2 — Install ExecuTorch

```bash
pip install executorch
# Or from source for the latest XNNPACK support:
# git clone https://github.com/pytorch/executorch && cd executorch
# pip install . --extra-index-url https://download.pytorch.org/whl/cpu
```

## Step 3 — Export to .pte (XNNPACK + 8da4w quantization)

```bash
python -m executorch.examples.models.llama.export_llama \
  --checkpoint    ./llama3_2_1b/original/consolidated.00.pth \
  --params        ./llama3_2_1b/original/params.json \
  --xnnpack \
  --quantize      8da4w \
  --max_seq_len   512 \
  --output_name   llama3_2_1b_xnnpack_q8.pte
```

> **Expected output size**: ~700 MB (8da4w = 8-bit activations, 4-bit weights)
> **Export time**: 10–20 minutes on a modern CPU

## Step 4 — Convert tokenizer

```bash
python -m executorch.examples.models.llama.tokenizer.tokenizer \
  --tokenizer_model ./llama3_2_1b/tokenizer.model \
  --output_file     tokenizer.bin
```

## Step 5 — Deploy to device

```bash
chmod +x scripts/deploy_llama.sh
./scripts/deploy_llama.sh llama3_2_1b_xnnpack_q8.pte tokenizer.bin
```

---

## Expected performance on Arm devices

| Device | SoC | Tokens/sec |
|--------|-----|-----------|
| Pixel 8 Pro | Tensor G3 (Cortex-X3) | ~8–12 tok/s |
| OnePlus 12 | Snapdragon 8 Gen 3 | ~10–15 tok/s |
| Samsung S24 | Exynos 2400 / SD 8 Gen 3 | ~8–14 tok/s |
| Raspberry Pi 5 | Cortex-A76 | ~1–2 tok/s |

For a 150-token explanation: **~10–20 seconds** on a flagship phone — fast enough for the demo.

---

## Alternative: Use the ExecuTorch demo app model

Meta provides pre-quantized Llama 3.2 1B `.pte` files for the ExecuTorch demo app:

```bash
# Check the ExecuTorch GitHub releases for pre-built .pte files:
# https://github.com/pytorch/executorch/releases
# Look for: llama3_2_1b_xnnpack_*.pte
```

This avoids the full export pipeline and is the fastest path for the demo.
