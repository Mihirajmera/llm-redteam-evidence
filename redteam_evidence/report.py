"""Assessment outputs: reviewer report (Markdown), per-control hashed evidence (JSON),
a machine-readable summary for `compare`, and OSCAL assessment results."""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .assess import CONTROLS
from .model import ControlResult, Run, TestResult

NS = 'https://github.com/Mihirajmera/llm-redteam-evidence'
FRAMEWORKS = {'owasp_llm': 'OWASP LLM', 'mitre_atlas': 'MITRE ATLAS', 'nist_ai_600_1': 'NIST AI 600-1',
              'nist_ai_rmf': 'NIST AI RMF', 'nist_800_53': 'NIST 800-53'}
EXCERPT = 300
STATUS_ICON = {'PASS': '✅ PASS', 'FAIL': '❌ FAIL', 'INCONCLUSIVE': '⚠️ INCONCLUSIVE', 'NOT_TESTED': '⬜ NOT TESTED'}


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def sha256(obj) -> str:
    return hashlib.sha256(canonical(obj).encode('utf-8')).hexdigest()


def _h(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def _excerpt(text: str) -> str:
    text = ' '.join(text.split())
    return text if len(text) <= EXCERPT else text[:EXCERPT] + '…'


def _pct(x: float) -> str:
    return f'{x * 100:.1f}%'


def _cell(v) -> str:
    return str(v).replace('|', '\\|').replace('\n', ' ')


def frameworks(cid: str) -> str:
    c = CONTROLS[cid]
    return '; '.join(f'{label} {", ".join(c[k])}' for k, label in FRAMEWORKS.items() if c.get(k))


def recommendation(controls: list[ControlResult]) -> str:
    statuses = {c.status for c in controls}
    if 'FAIL' in statuses:
        return 'BLOCK'
    if statuses & {'INCONCLUSIVE', 'NOT_TESTED'}:
        return 'REVIEW'
    return 'APPROVE'


def attempt_record(r: TestResult, excerpts: bool) -> dict:
    """Failing attempts can contain harmful model output. Hashes are always kept so the full
    text can be matched against the tool's raw output; excerpts are optional."""
    rec = {'tool': r.tool, 'test_id': r.test_id, 'strategy': r.strategy, 'detector': r.detector,
           'attempt_id': r.attempt_id, 'reason': _excerpt(r.reason),
           'prompt_sha256': _h(r.prompt), 'response_sha256': _h(r.response)}
    if excerpts:
        rec['prompt_excerpt'] = _excerpt(r.prompt)
        rec['response_excerpt'] = _excerpt(r.response)
    return rec


def run_record(run: Run) -> dict:
    scored = [r for r in run.results if not r.errored]
    return {'tool': run.tool, 'tool_version': run.tool_version, 'target': run.target,
            'started': run.started, 'source_file': run.source_file, 'source_sha256': run.source_sha256,
            'attempts': len(run.results), 'scored': len(scored),
            'failures': sum(1 for r in scored if not r.passed)}


# --------------------------------------------------------------------------- writers

def build_time() -> datetime:
    """Now, or SOURCE_DATE_EPOCH when set (the reproducible-builds convention), so a rerun on the
    same inputs can produce byte-identical output."""
    epoch = os.environ.get('SOURCE_DATE_EPOCH')
    if epoch:
        return datetime.fromtimestamp(int(epoch), timezone.utc)
    return datetime.now(timezone.utc).replace(microsecond=0)


def _uid(*parts) -> str:
    """Deterministic UUID: the same assessment at the same time always gets the same IDs."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, 'llm-redteam-evidence:' + '/'.join(map(str, parts))))


def write_all(runs: list[Run], controls: list[ControlResult], unmapped: Counter, out: Path, *,
              system: str, version: str, excerpts: bool = True, generated: datetime | None = None) -> dict[str, Path]:
    generated = generated or build_time()
    out.mkdir(parents=True, exist_ok=True)
    meta = {'system': system, 'version': version, 'generated': generated.isoformat(),
            'recommendation': recommendation(controls), 'runs': [run_record(r) for r in runs]}
    evidence = write_evidence(controls, meta, out / 'evidence', excerpts)
    return {
        'summary': write_summary(controls, unmapped, meta, evidence, out / 'summary.json'),
        'report': write_markdown(controls, unmapped, meta, evidence, out / 'report.md', excerpts),
        'oscal': write_oscal(controls, meta, evidence, out / 'oscal' / 'assessment-results.json'),
        **{f'evidence:{k}': v[0] for k, v in evidence.items()},
    }


def write_evidence(controls, meta, folder: Path, excerpts: bool) -> dict[str, tuple[Path, str]]:
    folder.mkdir(parents=True, exist_ok=True)
    index = {}
    for c in controls:
        hashed = {
            'control_id': c.control_id,
            'system': meta['system'], 'version': meta['version'],
            'sources': [{k: r[k] for k in ('tool', 'source_file', 'source_sha256')} for r in meta['runs']],
            'result': {k: v for k, v in asdict(c).items() if k != 'failing'},
            'failing_attempts': [attempt_record(r, excerpts) for r in c.failing],
        }
        record = {**hashed, 'title': c.title, 'frameworks': {k: CONTROLS[c.control_id].get(k, []) for k in FRAMEWORKS},
                  'generated': meta['generated'], 'sha256': sha256(hashed),
                  'hash_scope': 'sha256 of canonical JSON (sorted keys, no spaces) of every field except '
                                'title, frameworks, generated, sha256 and hash_scope'}
        path = folder / f'{c.control_id}.json'
        path.write_text(json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False) + '\n', encoding='utf-8', newline='\n')
        index[c.control_id] = (path, record['sha256'])
    return index


def write_summary(controls, unmapped, meta, evidence, path: Path) -> Path:
    doc = {**meta,
           'controls': [{**{k: v for k, v in asdict(c).items() if k != 'failing'},
                         'evidence_sha256': evidence[c.control_id][1]} for c in controls],
           'unmapped_tests': dict(sorted(unmapped.items()))}
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + '\n', encoding='utf-8', newline='\n')
    return path


def write_markdown(controls, unmapped, meta, evidence, path: Path, excerpts: bool) -> Path:
    rec = meta['recommendation']
    banner = {'BLOCK': '❌ **BLOCK**: at least one control exceeds its risk tolerance.',
              'REVIEW': '⚠️ **REVIEW**: no tolerance exceeded, but some controls lack enough evidence.',
              'APPROVE': '✅ **APPROVE**: every control is within tolerance with sufficient evidence.'}[rec]
    total = sum(r['scored'] for r in meta['runs'])
    L = [f'# LLM red-team assessment: {_cell(meta["system"])} {_cell(meta["version"])}', '',
         f'Release recommendation: {banner}', '',
         f'{total} scored attacks from {len(meta["runs"])} tool run(s), assessed against {len(controls)} controls. '
         f'Generated {meta["generated"]}.', '',
         '## Sources', '', '| Tool | Version | Target | Scored attacks | Succeeded | Errored | Raw output sha256 |',
         '|---|---|---|---:|---:|---:|---|']
    for r in meta['runs']:
        L.append(f'| {r["tool"]} | {_cell(r["tool_version"])} | {_cell(r["target"])} | {r["scored"]} | '
                 f'{r["failures"]} | {r["attempts"] - r["scored"]} | `{r["source_sha256"][:16]}…` |')
    if any(r['attempts'] > r['scored'] for r in meta['runs']):
        L += ['', 'Errored attempts (timeouts, provider errors) never produced a scorable answer and are '
              'excluded from every rate. A high error count is itself a finding: those attacks were not tested.']

    L += ['', '## Control results', '',
          '| Control | Status | Attacks | Succeeded | Errored | Attack success rate | 95% upper bound | Tolerance | Frameworks |',
          '|---|---|---:|---:|---:|---:|---:|---:|---|']
    for c in controls:
        L.append(f'| **{c.control_id}** {c.title} | {STATUS_ICON[c.status]} | {c.tests} | {c.failures} | {c.errors} | '
                 f'{_pct(c.attack_success_rate)} | {_pct(c.upper_bound_95) if c.tests else "–"} | '
                 f'{_pct(c.max_attack_success_rate)} | {frameworks(c.control_id)} |')
    L += ['', '*Attack success rate* is the share of scored attacks the model failed to resist. '
          'The *95% upper bound* (Wilson interval) is how high the true rate could plausibly be given the sample size; '
          'a control is INCONCLUSIVE when it is within tolerance but has fewer attacks than its minimum.']

    gaps = [c for c in controls if c.status in {'NOT_TESTED', 'INCONCLUSIVE'}]
    if gaps:
        L += ['', '## Coverage gaps', '']
        for c in gaps:
            need = 'no attacks were run' if c.status == 'NOT_TESTED' else f'only {c.tests} of the {c.min_tests} attacks required'
            L.append(f'- **{c.control_id}** {c.title}: {need}.')
    if unmapped:
        L += ['', '## Unmapped tests', '',
              'These tests ran but match no control in `catalog.yaml`, so they are not counted as evidence:', '']
        L += [f'- `{k}` ({v} attempts)' for k, v in sorted(unmapped.items())]

    failed = [c for c in controls if c.failures]
    if failed:
        L += ['', '## Failing attacks', '']
    for c in failed:
        L += [f'### {c.control_id} {c.title}', '',
              f'Evidence: `evidence/{c.control_id}.json` (sha256 `{evidence[c.control_id][1][:16]}…`)', '',
              '| Test | Attacks | Succeeded |', '|---|---:|---:|']
        L += [f'| `{_cell(k)}` | {v["tests"]} | {v["failures"]} |' for k, v in c.by_test.items() if v['failures']]
        if excerpts:
            L += ['', '<details><summary>Example attacks the model did not resist</summary>', '']
            examples = list({(r.tool, r.test_id, r.strategy): r for r in reversed(c.failing)}.values())[::-1]
            for r in examples[:3]:                   # one example per distinct test
                L += [f'- **{_cell(r.test_id)}**' + (f' via `{r.strategy}`' if r.strategy else ''),
                      f'  - Prompt: {_cell(_excerpt(r.prompt)) or "(not recorded)"}',
                      f'  - Response: {_cell(_excerpt(r.response)) or "(not recorded)"}']
                if r.reason:
                    L.append(f'  - Grader: {_cell(_excerpt(r.reason))}')
            L += ['', '</details>']
        L.append('')

    L += ['', '## Sign-off', '',
          '| Role | Decision | Name | Date |', '|---|---|---|---|',
          '| AI risk owner | ☐ Approve release ☐ Accept risk with exceptions ☐ Block | | |',
          '| Security reviewer | ☐ Concur ☐ Do not concur | | |']
    path.write_text('\n'.join(L) + '\n', encoding='utf-8', newline='\n')
    return path


def write_oscal(controls, meta, evidence, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    now = meta['generated']
    observations = []
    for r in meta['runs']:
        observations.append({
            'uuid': _uid(now, meta['version'], 'observation', r['source_sha256']),
            'title': f'{r["tool"]} run against {r["target"]}',
            'description': f'{r["scored"]} scored attacks, {r["failures"]} succeeded.',
            'methods': ['TEST'],
            'types': ['finding' if r['failures'] else 'control-objective'],
            'relevant-evidence': [{'href': r['source_file'], 'description': 'Raw red-team tool output',
                                   'props': [{'name': 'sha256', 'ns': NS, 'value': r['source_sha256']}]}],
            'collected': now,
        })
    obs_ids = [o['uuid'] for o in observations]
    findings = []
    for c in controls:
        state = 'not-satisfied' if c.status in {'FAIL', 'NOT_TESTED', 'INCONCLUSIVE'} else 'satisfied'
        props = [{'name': 'status', 'ns': NS, 'value': c.status},
                 {'name': 'attack-success-rate', 'ns': NS, 'value': f'{c.attack_success_rate:.4f}'},
                 {'name': 'tolerance', 'ns': NS, 'value': f'{c.max_attack_success_rate:.4f}'},
                 {'name': 'evidence-sha256', 'ns': NS, 'value': evidence[c.control_id][1]}]
        props += [{'name': 'framework-mapping', 'ns': NS, 'value': f'{label} {ref}'}
                  for k, label in FRAMEWORKS.items() for ref in CONTROLS[c.control_id].get(k, [])]
        findings.append({
            'uuid': _uid(now, meta['version'], 'finding', c.control_id),
            'title': f'{c.control_id}: {c.title}',
            'description': f'{c.failures} of {c.tests} attacks succeeded ({_pct(c.attack_success_rate)}); '
                           f'tolerance {_pct(c.max_attack_success_rate)}.',
            'props': props,
            'target': {'type': 'objective-id', 'target-id': c.control_id.lower(), 'status': {'state': state}},
            'related-observations': [{'observation-uuid': o} for o in obs_ids],
        })
    doc = {'assessment-results': {
        'uuid': _uid(now, meta['version'], 'assessment-results'),
        'metadata': {'title': f'LLM red-team assessment: {meta["system"]} {meta["version"]}',
                     'last-modified': now, 'version': meta['version'], 'oscal-version': '1.1.2'},
        'import-ap': {'href': '#'},
        'results': [{
            'uuid': _uid(now, meta['version'], 'result'),
            'title': f'Red-team assessment of {meta["system"]} {meta["version"]}',
            'description': f'Release recommendation: {meta["recommendation"]}.',
            'start': now, 'end': now,
            'reviewed-controls': {'control-selections': [
                {'include-controls': [{'control-id': c.control_id.lower()} for c in controls]}]},
            'observations': observations,
            'findings': findings,
        }],
    }}
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + '\n', encoding='utf-8', newline='\n')
    return path
