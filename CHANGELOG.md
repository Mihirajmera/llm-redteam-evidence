# Changelog

## Unreleased

- [Case study](case-studies/llama3.2-3b-garak/): a real garak 0.17 run against Llama 3.2 3B, assessed with `--no-excerpts`, plus a human review of the jailbreak detector's calls.
- garak 0.13+ reports: the target is read from `plugins.target_type` / `plugins.target_name` (it showed as "unknown").
- garak 0.17 probe modules are mapped: `web_injection.*` → RT-07 (the old `xss.*` name still maps), `sysprompt_extraction.*` → RT-04, `propile.*` → RT-05, and `fitd.*`, `dra.*`, `smuggling.*` → RT-03.

## 0.2.0 (2026-10-17)

- `redteam-evidence demo` assesses the bundled examples and compares v1 → v2 right after `pip install`; no clone needed.
- Committed [`sample-output/`](sample-output) so the reports can be read without running anything; CI checks it stays current.
- Reproducible output: set `SOURCE_DATE_EPOCH` for byte-identical evidence, summaries and OSCAL (deterministic OSCAL UUIDs, LF line endings on every OS).
- Sources inside a scanned folder are recorded relative to it, so evidence hashes don't depend on the install path.
- Dependencies pinned by hash; OpenSSF Scorecard workflow; contributing guide and issue forms.

## 0.1.0 (2026-10-16)

First release: garak and promptfoo parsers, 10 controls with risk tolerances and 95% confidence bounds, reviewer report, hashed evidence, OSCAL output and `compare` release gate.
