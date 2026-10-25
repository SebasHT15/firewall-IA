# V5 tokenizer remeasurement for dataset v3

Executed 2026-10-25 with `/usr/bin/python3.12`, `transformers` 5.8.0, the local TinyLlama tokenizer revision `fe8a4ea1ffedaf415f4da2f062534de366a451e6` from the ratified recipe `scripts/training/v5_training_recipe_v1.json` (SHA-256 `c9fe4a96a0f1159c0325ef785e105e6f39c69ca6b34cc99f97ddcdd5a29c04a6`). No network download.

Used `v5_train_data.measure_contract(tok, recipe)` with `AutoTokenizer.from_pretrained(..., local_files_only=True)`: template overhead **76**, longest fixed output budget **13**, max length **512**, margin **8**; `512-76-13-8 = B=415`, equal to the ratified value; no diagnostics. The tokenizer has 32,000 vocabulary entries. The maximum UTF-8 byte length among non-special decoded single tokens was **26** (within the assumed 48-byte upper bound); all **256** `<0xXX>` byte-fallback entries are present. These checks support the conservative byte bounds; they do not claim to test every possible concatenated string.

The dataset generator uses the stricter `utf8_bytes_upper_bound` counter. Exact trainer tokenization still runs again at `--gate-only` and at launch; this remeasurement does not replace those gates.
