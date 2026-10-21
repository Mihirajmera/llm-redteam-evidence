"""CLI.

  redteam-evidence demo                          assess the bundled examples and compare v1 -> v2
  redteam-evidence assess <results...> --system NAME --version LABEL [--out DIR]
  redteam-evidence compare <baseline/summary.json> <candidate/summary.json> [--fail-on-regression]
"""
from __future__ import annotations

import argparse
import sys
from argparse import Namespace
from pathlib import Path

from .assess import assess
from .compare import compare, load_summary, write_markdown as write_comparison
from .parsers import discover
from .report import recommendation, write_all

EXAMPLES = Path(__file__).parent / 'examples'
DEMO_SYSTEM = 'Acme Support Assistant'

EPILOG = """examples:
  redteam-evidence demo
  redteam-evidence assess ~/.local/share/garak/garak_runs/ --system "Support bot" --version v2 --out out/v2
  redteam-evidence assess results.json --system "Support bot" --version v2 --no-excerpts --fail-on fail
  redteam-evidence compare out/v1/summary.json out/v2/summary.json --fail-on-regression
"""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog='redteam-evidence',
                                 description='Turn LLM red-team results into audit evidence and a release gate.',
                                 epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)

    a = sub.add_parser('assess', help='assess garak / promptfoo results against the control catalog')
    a.add_argument('paths', nargs='+', type=Path, help='garak *.report.jsonl, promptfoo results JSON, or folders')
    a.add_argument('--system', required=True, help='name of the AI system under test')
    a.add_argument('--version', required=True, help='model / prompt / release label being assessed')
    a.add_argument('--out', type=Path, default=Path('assessment'), help='output folder (default: assessment)')
    a.add_argument('--no-excerpts', action='store_true',
                   help='keep only hashes of failing prompts and responses (no text) in the outputs')
    a.add_argument('--fail-on', choices=['fail', 'review', 'never'], default='never',
                   help='exit 1 on a BLOCK recommendation (fail) or on BLOCK or REVIEW (review)')

    c = sub.add_parser('compare', help='compare two assessments and flag regressions')
    c.add_argument('baseline', type=Path, help='summary.json of the approved version')
    c.add_argument('candidate', type=Path, help='summary.json of the new version')
    c.add_argument('--out', type=Path, default=Path('comparison.md'))
    c.add_argument('--max-increase', type=float, default=0.02,
                   help='allowed rise in attack success rate, absolute (default 0.02 = 2 points)')
    c.add_argument('--fail-on-regression', action='store_true', help='exit 1 if any control regressed')

    d = sub.add_parser('demo', help='assess the bundled synthetic examples and compare v1 -> v2 (no setup needed)')
    d.add_argument('--out', type=Path, default=Path('redteam-demo'), help='output folder (default: redteam-demo)')

    args = ap.parse_args(argv)
    if args.cmd == 'demo':
        return _demo(args.out)
    return _assess(args) if args.cmd == 'assess' else _compare(args)


def _demo(out: Path) -> int:
    print(f'Assessing the bundled synthetic examples in {EXAMPLES}\n')
    for version in ('v1', 'v2'):
        print(f'=== {DEMO_SYSTEM} {version}')
        _assess(Namespace(paths=[EXAMPLES / version], system=DEMO_SYSTEM, version=version,
                          out=out / version, no_excerpts=False, fail_on='never'))
        print()
    print('=== Release comparison v1 -> v2')
    _compare(Namespace(baseline=out / 'v1' / 'summary.json', candidate=out / 'v2' / 'summary.json',
                       out=out / 'comparison.md', max_increase=0.02, fail_on_regression=False))
    print(f'\nOpen {out / "v2" / "report.md"} for the full assessment and {out / "comparison.md"} for the '
          f'release gate.\nThe examples are synthetic; see the README for running garak or promptfoo '
          f'against a real model.')
    return 0


def _assess(args) -> int:
    missing = [p for p in args.paths if not p.exists()]
    if missing:
        print(f'not found: {", ".join(map(str, missing))}', file=sys.stderr)
        return 2
    runs = discover(args.paths)
    if not runs:
        print('No garak or promptfoo results found.', file=sys.stderr)
        return 2
    controls, unmapped = assess(runs)
    paths = write_all(runs, controls, unmapped, args.out, system=args.system, version=args.version,
                      excerpts=not args.no_excerpts)

    print(f'{"CONTROL":<8} {"STATUS":<16} {"ATTACKS":>8} {"SUCCEEDED":>10} {"ASR":>7} {"LIMIT":>7}')
    for c in controls:
        print(f'{c.control_id:<8} {c.status:<16} {c.tests:>8} {c.failures:>10} '
              f'{c.attack_success_rate * 100:>6.1f}% {c.max_attack_success_rate * 100:>6.1f}%')
    if unmapped:
        print(f'\n{sum(unmapped.values())} attempts from {len(unmapped)} unmapped test(s); see report.')
    rec = recommendation(controls)
    print(f'\nRecommendation: {rec}\nReport: {paths["report"]}\nOSCAL: {paths["oscal"]}')
    if args.fail_on == 'fail' and rec == 'BLOCK' or args.fail_on == 'review' and rec != 'APPROVE':
        return 1
    return 0


def _compare(args) -> int:
    base, cand = load_summary(args.baseline), load_summary(args.candidate)
    rows = compare(base, cand, args.max_increase)
    path = write_comparison(base, cand, rows, args.out, args.max_increase)
    regressions = [r for r in rows if r['regression']]
    for r in rows:
        flag = 'REGRESSION' if r['regression'] else ('improved' if r['improved'] else ('not significant' if r['unconfirmed'] else ''))
        print(f'{r["control_id"]:<8} {r["before_asr"] * 100:>6.1f}% -> {r["after_asr"] * 100:>6.1f}%  {flag}')
    print(f'\n{len(regressions)} regression(s). Comparison: {path}')
    return 1 if args.fail_on_regression and regressions else 0


if __name__ == '__main__':
    sys.exit(main())
