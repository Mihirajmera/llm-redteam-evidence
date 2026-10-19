"""Read red-team tool output into Run / TestResult.

* garak: the `*.report.jsonl` file. Each evaluated `attempt` line becomes one result; an attempt
  fails when any detector scored any output at or above garak's default 0.5 threshold. Reports
  without attempt lines fall back to the per-probe `eval` counts.
* promptfoo: the JSON written by `promptfoo eval -o results.json` / `promptfoo redteam eval`.
  Each test result becomes one result; `success: true` means the model resisted the attack.

Both formats have shifted between releases, so fields are read leniently.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from .model import Run, TestResult

GARAK_THRESHOLD = 0.5
# Summary-only garak reports are expanded into one result per counted attempt. Cap the count
# so a crafted "total" can't exhaust memory; real runs are orders of magnitude smaller.
MAX_EVAL_ATTEMPTS = 1_000_000


class ResultFileError(ValueError):
    """A file in a supported format whose structure or values aren't what the format requires."""


def load(path: Path) -> Run | None:
    """Parse one file. Returns None for files that are neither format. Raises ValueError
    (including ResultFileError) for malformed input, never anything else."""
    try:
        return _load(path)
    except (AttributeError, KeyError, TypeError, RecursionError) as e:
        raise ResultFileError(f'unexpected structure ({type(e).__name__}: {e})') from e


def _load(path: Path) -> Run | None:
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    text = raw.decode('utf-8-sig')
    first = text.lstrip()[:1]
    if path.suffix.lower() == '.jsonl' or (first == '{' and '"entry_type"' in text[:2000]):
        lines = [json.loads(line) for line in text.splitlines() if line.strip()]
        if any(isinstance(e, dict) and 'entry_type' in e for e in lines):
            return parse_garak(path, digest, lines)
    if path.suffix.lower() == '.json':
        data = json.loads(text)
        if isinstance(data, dict) and _promptfoo_results(data) is not None:
            return parse_promptfoo(path, digest, data)
    return None


def discover(paths: list[Path]) -> list[Run]:
    runs = []
    for p in paths:
        files = sorted(f for f in p.rglob('*') if f.suffix.lower() in {'.json', '.jsonl'}) if p.is_dir() else [p]
        for f in files:
            try:
                run = load(f)
            except ValueError as e:
                print(f'warning: skipped {f}: {type(e).__name__}: {e}', file=sys.stderr)
                continue
            if run:
                if p.is_dir():
                    # "<folder>/<relative path>", so evidence (and its hash) doesn't depend on
                    # where the folder sits on this machine
                    run.source_file = f'{p.name}/{f.relative_to(p).as_posix()}'
                runs.append(run)
    return runs


# --------------------------------------------------------------------------- garak

def parse_garak(path: Path, digest: str, entries: list[dict]) -> Run:
    setup = next((e for e in entries if e.get('entry_type') == 'start_run setup'), {})
    init = next((e for e in entries if e.get('entry_type') == 'init'), {})
    run = Run(
        tool='garak',
        tool_version=str(init.get('garak_version') or setup.get('_config.version') or 'unknown'),
        # garak 0.13+ renamed plugins.model_* to plugins.target_*; older reports use the model_* keys
        target=' / '.join(str(v) for v in (setup.get('plugins.target_type') or setup.get('plugins.model_type'),
                                           setup.get('plugins.target_name') or setup.get('plugins.model_name')) if v)
               or 'unknown',
        started=str(init.get('start_time', '')),
        source_file=path.as_posix(),
        source_sha256=digest,
    )
    attempts = [e for e in entries if e.get('entry_type') == 'attempt' and e.get('status') == 2]
    if attempts:
        for a in attempts:
            scores = {d: [s for s in (v or []) if s is not None] for d, v in (a.get('detector_results') or {}).items()}
            hit = [d for d, v in scores.items() if any(s >= GARAK_THRESHOLD for s in v)]
            run.results.append(TestResult(
                tool='garak',
                test_id=a.get('probe_classname', 'unknown'),
                passed=not hit,
                detector=', '.join(hit or sorted(scores)) or None,
                prompt=_garak_prompt(a.get('prompt')),
                response=' | '.join(_text(o) for o in a.get('outputs') or [] if _text(o)),
                reason=f"detector score >= {GARAK_THRESHOLD}: {', '.join(hit)}" if hit else '',
                attempt_id=str(a.get('uuid', '')),
                errored=not scores,
            ))
    else:
        # Summary-only report: rebuild results from the per-probe pass counts.
        for e in entries:
            if e.get('entry_type') != 'eval':
                continue
            total, passed = int(e.get('total', 0)), int(e.get('passed', 0))
            if not 0 <= passed <= total <= MAX_EVAL_ATTEMPTS:
                raise ResultFileError(f'implausible eval counts for {e.get("probe")}: passed={passed}, total={total}')
            for i in range(total):
                run.results.append(TestResult(tool='garak', test_id=e.get('probe', 'unknown'),
                                              passed=i < passed, detector=e.get('detector'),
                                              attempt_id=f"{e.get('probe')}#{i}"))
    return run


def _garak_prompt(prompt) -> str:
    if isinstance(prompt, str):
        return prompt
    if isinstance(prompt, dict):                       # garak >= 0.11 Conversation object
        turns = prompt.get('turns') or []
        return ' | '.join(_text(t.get('content')) for t in turns if isinstance(t, dict) and _text(t.get('content')))
    return ''


def _text(value) -> str:
    if value is None:
        return ''
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return str(value.get('text') or value.get('output') or '')
    return str(value)


# --------------------------------------------------------------------------- promptfoo

def _promptfoo_results(data: dict) -> list | None:
    inner = data.get('results')
    if isinstance(inner, dict) and isinstance(inner.get('results'), list):
        return inner['results']
    if isinstance(inner, list) and inner and isinstance(inner[0], dict) and 'success' in inner[0]:
        return inner
    return None


def parse_promptfoo(path: Path, digest: str, data: dict) -> Run:
    results = _promptfoo_results(data) or []
    inner = data.get('results') if isinstance(data.get('results'), dict) else {}
    providers = sorted({_provider(r) for r in results if _provider(r)})
    run = Run(
        tool='promptfoo',
        tool_version=str((data.get('metadata') or {}).get('promptfooVersion') or data.get('version') or 'unknown'),
        target=', '.join(providers) or 'unknown',
        started=str(inner.get('timestamp') or data.get('createdAt') or ''),
        source_file=path.as_posix(),
        source_sha256=digest,
    )
    for r in results:
        meta = {**((r.get('testCase') or {}).get('metadata') or {}), **(r.get('metadata') or {})}
        grading = r.get('gradingResult') or {}
        response = r.get('response') or {}
        run.results.append(TestResult(
            tool='promptfoo',
            test_id=str(meta.get('pluginId') or 'unknown'),
            strategy=meta.get('strategyId') or None,
            passed=bool(r.get('success')),
            detector=(str((grading.get('assertion') or {}).get('type') or 'llm-rubric')) if grading else None,
            prompt=_text((r.get('prompt') or {}).get('raw') if isinstance(r.get('prompt'), dict) else r.get('prompt')),
            response=_text(response.get('output') if isinstance(response, dict) else response),
            reason=str(grading.get('reason') or ''),
            attempt_id=str(r.get('id') or ''),
            errored=bool(r.get('error')) or r.get('failureReason') == 2,
        ))
    return run


def _provider(r: dict) -> str:
    p = r.get('provider')
    if isinstance(p, dict):
        return str(p.get('label') or p.get('id') or '')
    return str(p or '')
