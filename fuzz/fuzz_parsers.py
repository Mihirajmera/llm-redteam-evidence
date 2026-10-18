"""Fuzz redteam_evidence.parsers.load with arbitrary bytes.

The parser reads files that may come from untrusted sources. For malformed input it must raise
one of the documented errors (ValueError); any other exception, hang or crash is a bug.
"""
import sys
import tempfile
from pathlib import Path

import atheris

with atheris.instrument_imports():
    from redteam_evidence.parsers import load

TMP = tempfile.mkdtemp()
PATHS = [Path(TMP) / f"input{suffix}" for suffix in ['.json', '.jsonl']]


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    path = PATHS[fdp.ConsumeIntInRange(0, len(PATHS) - 1)]
    path.write_bytes(fdp.ConsumeBytes(fdp.remaining_bytes()))
    try:
        load(path)
    except (ValueError):
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
