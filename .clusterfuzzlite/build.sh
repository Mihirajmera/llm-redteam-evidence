#!/bin/bash -eu
# Runtime dependencies, pinned by version and hash.

# Bundle every fuzz target with the package (and any data files it loads at import time).
for fuzzer in $(find "$SRC/llm-redteam-evidence/fuzz" -name 'fuzz_*.py'); do
  compile_python_fuzzer "$fuzzer" --paths "$SRC/llm-redteam-evidence"
done
