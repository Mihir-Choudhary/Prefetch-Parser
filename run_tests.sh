#!/usr/bin/env bash
# Run the whole regression suite. Every one of these must stay green.
#
# Ordered cheapest-first so a broken parser fails in seconds rather than after the
# corpus-wide ingests. Each script is self-checking and exits non-zero on drift.
set -uo pipefail
cd "$(dirname "$0")/reference" || exit 1

SUITE=(
    validate_spec        # the format spec itself, 683 files
    test_core_vs_spec    # prefetch_core == spec parser, 690 files, all 5 versions
    fuzz_parser          # malformed input never crashes; all 7 stages exercised
    compare_pathsources  # 5a-vs-filename-list resolver counts
    edge_cases           # every number in docs/edge-cases.md
    diff_against_pecmd   # agreement with real PECmd output
    test_store           # SQLite relational invariants
    test_csv_coverage    # CSV is a strict superset of PECmd's columns
    test_gui_logic       # GUI filter/sort/tag semantics, headless
    test_artifacts       # non-.pf artifacts match the manual byte-level analysis
    test_csv_escaping    # list-cell escaping survives hostile filenames
    test_cli_errors      # CLI fails usefully and never discards a run
    test_layering        # core stays Qt-free; frozen-build guards present
    test_memory          # memory per record stays bounded; lazy chains stay correct
    test_ads             # ADS recovery logic + the carrier-timestamp rule
    test_output_fidelity # every output surface matches the parsed record exactly
)

fail=0
for s in "${SUITE[@]}"; do
    printf '%-22s ' "$s"
    if out=$(timeout 900 python3 "$s.py" 2>&1); then
        echo "PASS"
    else
        echo "FAIL"
        echo "$out" | tail -20 | sed 's/^/    /'
        fail=$((fail + 1))
    fi
done

echo
if [ "$fail" -eq 0 ]; then
    echo "all ${#SUITE[@]} suites green"
else
    echo "$fail of ${#SUITE[@]} suites FAILED"
fi
exit "$fail"
