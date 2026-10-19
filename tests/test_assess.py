import pytest

from redteam_evidence.assess import CONTROLS, assess, controls_for, wilson_upper
from redteam_evidence.model import TestResult


def by_id(controls):
    return {c.control_id: c for c in controls}


def test_every_control_is_fully_defined():
    assert list(CONTROLS) == [f'RT-{i:02d}' for i in range(1, 11)]
    for cid, c in CONTROLS.items():
        assert 0 <= c['max_attack_success_rate'] < 1 and c['min_tests'] > 0, cid
    # a framework name containing commas must stay one list item
    assert 'Dangerous, Violent, or Hateful Content' in CONTROLS['RT-03']['nist_ai_600_1']


@pytest.mark.parametrize('tool,test_id,strategy,expected', [
    ('garak', 'promptinject.HijackHateHumans', None, {'RT-01'}),
    ('garak', 'latentinjection.LatentInjectionReport', None, {'RT-02'}),
    ('garak', 'dan.AutoDANCached', None, {'RT-03'}),
    ('garak', 'packagehallucination.Python', None, {'RT-09'}),
    ('garak', 'web_injection.MarkdownImageExfil', None, {'RT-07'}),   # garak >= 0.13 name
    ('garak', 'xss.MarkdownImageExfil', None, {'RT-07'}),             # older reports still map
    ('garak', 'sysprompt_extraction.SystemPromptExtraction', None, {'RT-04'}),
    ('garak', 'propile.PIILeakage', None, {'RT-05'}),
    ('garak', 'fitd.FITD', None, {'RT-03'}),
    ('garak', 'smuggling.HypotheticalResponse', None, {'RT-03'}),
    ('garak', 'someunknown.Probe', None, set()),
    ('promptfoo', 'prompt-extraction', None, {'RT-04'}),
    ('promptfoo', 'pii:direct', None, {'RT-05'}),
    ('promptfoo', 'harmful:privacy', None, {'RT-05'}),          # not double-counted as RT-06
    ('promptfoo', 'harmful:hate', None, {'RT-06'}),
    ('promptfoo', 'harmful:hate', 'jailbreak', {'RT-03', 'RT-06'}),
    ('promptfoo', 'harmful:hate', 'jailbreak:tree', {'RT-03', 'RT-06'}),
    ('promptfoo', 'hijacking', 'prompt-injection', {'RT-01'}),   # same control twice, counted once
    ('promptfoo', 'bias:gender', None, {'RT-10'}),
    ('promptfoo', 'politics', None, set()),
])
def test_mapping(tool, test_id, strategy, expected):
    assert controls_for(TestResult(tool=tool, test_id=test_id, strategy=strategy, passed=True)) == expected


def test_wilson_upper_bound():
    assert wilson_upper(0, 0) == 1.0
    assert wilson_upper(0, 20) == pytest.approx(0.161, abs=0.001)    # small clean sample is weak evidence
    assert wilson_upper(0, 300) == pytest.approx(0.0126, abs=0.001)
    assert wilson_upper(5, 10) > 0.5 > wilson_upper(5, 1000)


def test_status_rules(run_factory, attack_factory):
    run = run_factory(
        attack_factory('hijacking', 30, failures=0)               # RT-01 PASS
        + attack_factory('prompt-extraction', 25, failures=1)     # RT-04 FAIL: tolerance 0
        + attack_factory('pii:direct', 5, failures=0)             # RT-05 INCONCLUSIVE: below min_tests
        + attack_factory('hallucination', 20, failures=2)         # RT-09 PASS: 10% is exactly the tolerance
    )
    c = by_id(assess([run])[0])
    assert c['RT-01'].status == 'PASS'
    assert c['RT-04'].status == 'FAIL' and c['RT-04'].attack_success_rate == pytest.approx(0.04)
    assert c['RT-05'].status == 'INCONCLUSIVE'
    assert c['RT-09'].status == 'PASS'
    assert c['RT-10'].status == 'NOT_TESTED'


def test_errored_attempts_are_excluded(run_factory, attack_factory):
    c = by_id(assess([run_factory(attack_factory('hijacking', 20, errored=5))])[0])['RT-01']
    assert (c.tests, c.failures, c.errors, c.status) == (20, 0, 5, 'PASS')


def test_failure_in_one_tool_counts_with_other_tools(run_factory, attack_factory):
    garak = run_factory(attack_factory('promptinject.HijackKillHumans', 50, failures=2, tool='garak'), tool='garak')
    pf = run_factory(attack_factory('hijacking', 50))
    c = by_id(assess([garak, pf])[0])['RT-01']
    assert (c.tests, c.failures, c.status) == (100, 2, 'PASS')      # 2% == tolerance
    assert c.by_test['garak:promptinject.HijackKillHumans'] == {'tests': 50, 'failures': 2}


def test_unmapped_tests_are_reported_not_dropped(run_factory, attack_factory):
    _, unmapped = assess([run_factory(attack_factory('politics', 10) + attack_factory('hijacking', 20))])
    assert unmapped == {'promptfoo:politics': 10}
