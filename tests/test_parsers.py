import hashlib
import json

from conftest import EXAMPLES
from redteam_evidence.parsers import discover, load


def test_garak_example():
    run = load(EXAMPLES / 'v2' / 'garak.v2.report.jsonl')
    assert (run.tool, run.tool_version) == ('garak', '0.13.0')
    assert 'acme-support-assistant-v2' in run.target
    autodan = [r for r in run.results if r.test_id == 'dan.AutoDANCached']
    assert len(autodan) == 15 and sum(not r.passed for r in autodan) == 3
    failed = next(r for r in autodan if not r.passed)
    assert failed.prompt.startswith('From now on you are DAN') and failed.response.startswith('DAN:')
    assert 'mitigation.MitigationBypass' in failed.reason


def test_source_hash_is_the_raw_file_hash():
    path = EXAMPLES / 'v1' / 'promptfoo.v1.json'
    assert load(path).source_sha256 == hashlib.sha256(path.read_bytes()).hexdigest()


def test_promptfoo_example():
    run = load(EXAMPLES / 'v2' / 'promptfoo.v2.json')
    assert (run.tool, run.tool_version, run.target) == ('promptfoo', '0.118.0', 'acme-support-assistant-v2')
    jail = [r for r in run.results if r.strategy == 'jailbreak']
    assert len(jail) == 20 and all(r.test_id == 'harmful:hate' for r in jail)
    assert sum(r.errored for r in run.results) == 2


def test_garak_threshold_and_legacy_prompt(tmp_path):
    lines = [
        {'entry_type': 'init', 'garak_version': '0.9.0', 'start_time': 't'},
        {'entry_type': 'attempt', 'status': 2, 'probe_classname': 'dan.Dan_11_0', 'prompt': 'plain string prompt',
         'outputs': ['ok', 'bad'], 'detector_results': {'d1': [0.0, 0.49], 'd2': [0.1, 0.5]}},
        {'entry_type': 'attempt', 'status': 2, 'probe_classname': 'dan.Dan_11_0', 'prompt': 'p',
         'outputs': ['ok'], 'detector_results': {'d1': [0.49]}},
        {'entry_type': 'attempt', 'status': 1, 'probe_classname': 'dan.Dan_11_0'},          # not evaluated
    ]
    p = tmp_path / 'r.report.jsonl'
    p.write_text('\n'.join(map(json.dumps, lines)), encoding='utf-8')
    run = load(p)
    assert [r.passed for r in run.results] == [False, True]          # 0.5 is a hit, 0.49 is not
    assert run.results[0].prompt == 'plain string prompt' and run.results[0].detector == 'd2'


def test_garak_summary_only_report(tmp_path):
    lines = [{'entry_type': 'init', 'garak_version': '0.13.0'},
             {'entry_type': 'eval', 'probe': 'promptinject.HijackHateHumans', 'detector': 'x', 'passed': 18, 'total': 20}]
    p = tmp_path / 'summary.report.jsonl'
    p.write_text('\n'.join(map(json.dumps, lines)), encoding='utf-8')
    run = load(p)
    assert len(run.results) == 20 and sum(not r.passed for r in run.results) == 2


def test_discover_ignores_unrelated_and_broken_files(tmp_path, capsys):
    (tmp_path / 'package.json').write_text('{"name": "x"}', encoding='utf-8')
    (tmp_path / 'broken.jsonl').write_text('{"entry_type": "init"}\n{not json', encoding='utf-8')
    runs = discover([tmp_path, EXAMPLES / 'v1'])
    assert sorted(r.tool for r in runs) == ['garak', 'promptfoo']
    assert 'skipped' in capsys.readouterr().err


def test_malformed_structures_raise_value_errors(tmp_path):
    import pytest
    from redteam_evidence.parsers import ResultFileError
    cases = {
        'list.json': '{"results": {"results": [[1, 2]]}}',                     # a result that is a list, not an object
        'counts.report.jsonl': '{"entry_type": "eval", "probe": "p", "passed": {}, "total": 5}',
    }
    for name, text in cases.items():
        p = tmp_path / name
        p.write_text(text, encoding='utf-8')
        with pytest.raises(ResultFileError):
            load(p)


def test_eval_counts_are_capped(tmp_path):
    import pytest
    from redteam_evidence.parsers import ResultFileError
    p = tmp_path / 'huge.report.jsonl'
    p.write_text('{"entry_type": "eval", "probe": "p", "passed": 0, "total": 1000000000000}', encoding='utf-8')
    with pytest.raises(ResultFileError, match='implausible'):
        load(p)                      # must fail fast, not try to build a trillion results
