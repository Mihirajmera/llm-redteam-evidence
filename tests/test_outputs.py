import json

import pytest

from conftest import EXAMPLES
from redteam_evidence.__main__ import main
from redteam_evidence.compare import compare, load_summary
from redteam_evidence.assess import assess
from redteam_evidence.report import sha256, write_all

HASHED = ('control_id', 'system', 'version', 'sources', 'result', 'failing_attempts')


@pytest.fixture(scope='module')
def assessed(tmp_path_factory):
    out = tmp_path_factory.mktemp('assessments')
    for v in ('v1', 'v2'):
        assert main(['assess', str(EXAMPLES / v), '--system', 'Acme', '--version', v, '--out', str(out / v)]) == 0
    return out


def test_recommendations(assessed):
    assert load_summary(assessed / 'v1' / 'summary.json')['recommendation'] == 'REVIEW'   # RT-10 never tested
    assert load_summary(assessed / 'v2' / 'summary.json')['recommendation'] == 'BLOCK'


def test_evidence_hash_detects_tampering(assessed):
    rec = json.loads((assessed / 'v2' / 'evidence' / 'RT-04.json').read_text(encoding='utf-8'))
    hashed = {k: rec[k] for k in HASHED}
    assert sha256(hashed) == rec['sha256']
    hashed['result']['failures'] = 0
    assert sha256(hashed) != rec['sha256']


def test_failing_attempts_keep_hashes_and_excerpts(assessed):
    rec = json.loads((assessed / 'v2' / 'evidence' / 'RT-04.json').read_text(encoding='utf-8'))
    assert len(rec['failing_attempts']) == 4
    a = rec['failing_attempts'][0]
    assert len(a['prompt_sha256']) == 64 and a['response_excerpt'].startswith('You are AcmeBot')


def test_no_excerpts_keeps_text_out_of_every_output(tmp_path):
    out = tmp_path / 'redacted'
    main(['assess', str(EXAMPLES / 'v2'), '--system', 'Acme', '--version', 'v2', '--out', str(out), '--no-excerpts'])
    blob = ''.join(p.read_text(encoding='utf-8') for p in out.rglob('*') if p.is_file())
    assert 'ESC-ACME-EXAMPLE' not in blob and 'j.rivera@example.com' not in blob
    rec = json.loads((out / 'evidence' / 'RT-05.json').read_text(encoding='utf-8'))
    assert 'response_excerpt' not in rec['failing_attempts'][0] and rec['failing_attempts'][0]['response_sha256']


def test_oscal(assessed):
    doc = json.loads((assessed / 'v2' / 'oscal' / 'assessment-results.json').read_text(encoding='utf-8'))
    res = doc['assessment-results']['results'][0]
    states = {f['target']['target-id']: f['target']['status']['state'] for f in res['findings']}
    assert states['rt-04'] == 'not-satisfied' and states['rt-01'] == 'satisfied'
    assert len(res['observations']) == 2
    props = {p['value'] for f in res['findings'] if f['target']['target-id'] == 'rt-04' for p in f['props']}
    assert {'OWASP LLM LLM07', 'MITRE ATLAS AML.T0056'} <= props


def test_compare_finds_the_regressions(assessed):
    rows = compare(load_summary(assessed / 'v1' / 'summary.json'), load_summary(assessed / 'v2' / 'summary.json'))
    assert [r['control_id'] for r in rows if r['regression']] == ['RT-03', 'RT-04', 'RT-05', 'RT-06']
    assert [r['control_id'] for r in rows if r['improved']] == ['RT-10']
    # 6.7% -> 4.4% on 45 attempts each is within noise: not credited as an improvement
    assert [r['control_id'] for r in rows if r['unconfirmed']] == ['RT-09']


def _summary(version, failures, tests, status='FAIL'):
    return {'system': 'Acme', 'version': version, 'generated': 't', 'controls': [
        {'control_id': 'RT-03', 'title': 'Jailbreaks', 'status': status, 'tests': tests, 'failures': failures,
         'attack_success_rate': failures / tests, 'by_test': {}}]}


@pytest.mark.parametrize('before,after,regression,unconfirmed', [
    ((2, 4), (3, 4), False, True),          # +25 pts on 4 attempts: noise, needs more testing
    ((20, 200), (40, 200), True, False),    # +10 pts on 200 attempts: z = 2.8, a real regression
    ((20, 200), (24, 200), False, True),    # +2 pts above threshold but not significant
    ((20, 200), (20, 200), False, False),
])
def test_regressions_must_be_significant(before, after, regression, unconfirmed):
    [row] = compare(_summary('v1', *before), _summary('v2', *after), max_increase=0.01)
    assert row['regression'] is regression and row['unconfirmed'] is unconfirmed


def test_significant_drop_is_an_improvement():
    [row] = compare(_summary('v1', 113, 256), _summary('v2', 57, 256))
    assert row['improved'] and row['z'] < -5


def test_compare_cli_gate(assessed, tmp_path):
    v1, v2 = str(assessed / 'v1' / 'summary.json'), str(assessed / 'v2' / 'summary.json')
    assert main(['compare', v1, v2, '--out', str(tmp_path / 'c.md')]) == 0
    assert main(['compare', v1, v2, '--out', str(tmp_path / 'c.md'), '--fail-on-regression']) == 1
    assert main(['compare', v1, v1, '--out', str(tmp_path / 'same.md'), '--fail-on-regression']) == 0
    assert 'RT-04' in (tmp_path / 'c.md').read_text(encoding='utf-8')


def test_assess_gate(tmp_path):
    args = ['assess', str(EXAMPLES / 'v2'), '--system', 'Acme', '--version', 'v2', '--out', str(tmp_path)]
    assert main(args + ['--fail-on', 'fail']) == 1
    assert main(['assess', str(EXAMPLES / 'v1'), '--system', 'Acme', '--version', 'v1',
                 '--out', str(tmp_path / 'v1'), '--fail-on', 'fail']) == 0     # REVIEW is not BLOCK
    assert main(['assess', str(tmp_path / 'nothing-here'), '--system', 'x', '--version', 'y']) == 2


def test_demo(tmp_path, capsys):
    assert main(['demo', '--out', str(tmp_path / 'demo')]) == 0
    out = capsys.readouterr().out
    assert 'Recommendation: REVIEW' in out and 'Recommendation: BLOCK' in out and '4 regression(s)' in out
    assert (tmp_path / 'demo' / 'comparison.md').exists()
    # sources are recorded relative to the scanned folder, not this machine's install path
    summary = load_summary(tmp_path / 'demo' / 'v2' / 'summary.json')
    assert sorted(r['source_file'] for r in summary['runs']) == ['v2/garak.v2.report.jsonl', 'v2/promptfoo.v2.json']


def test_output_is_reproducible(tmp_path, monkeypatch):
    monkeypatch.setenv('SOURCE_DATE_EPOCH', '1791763200')
    for run in ('a', 'b'):
        main(['demo', '--out', str(tmp_path / run)])
    files = sorted(p.relative_to(tmp_path / 'a') for p in (tmp_path / 'a').rglob('*') if p.is_file())
    assert len(files) > 20
    for f in files:
        assert (tmp_path / 'a' / f).read_bytes() == (tmp_path / 'b' / f).read_bytes(), f


@pytest.mark.parametrize('scored,failures,errors', [(20, 1, 5), (0, 0, 3), (20, 0, 0)])
def test_report_shows_errors_per_control(tmp_path, run_factory, attack_factory, scored, failures, errors):
    runs = [run_factory(attack_factory('hijacking', scored, failures=failures, errored=errors))]
    controls, unmapped = assess(runs)
    paths = write_all(runs, controls, unmapped, tmp_path, system='Acme', version='test')
    report = paths['report'].read_text(encoding='utf-8')
    table = report.split('## Control results\n', 1)[1].strip().split('\n\n', 1)[0]
    lines = table.splitlines()
    assert lines[0].split(' | ')[1:6] == ['Status', 'Attacks', 'Succeeded', 'Errored', 'Attack success rate']
    assert len(lines[0].split('|')) == len(lines[1].split('|'))
    for control in controls:
        row = next(line for line in lines[2:] if line.startswith(f'| **{control.control_id}**'))
        cells = row.split(' | ')
        assert cells[2:5] == [str(control.tests), str(control.failures), str(control.errors)]
        assert cells[5] == f'{control.attack_success_rate * 100:.1f}%'
