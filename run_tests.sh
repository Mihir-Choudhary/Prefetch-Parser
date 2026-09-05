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
    test_vendor_truth    # 224 expected values from an INDEPENDENT implementation's own tests
    fuzz_parser          # malformed input never crashes; all 7 stages exercised
    compare_pathsources  # 5a-vs-filename-list resolver counts
    edge_cases           # every number in docs/edge-cases.md
    diff_against_pecmd   # agreement with real PECmd output
    test_store           # SQLite relational invariants
    test_csv_coverage    # CSV is a strict superset of PECmd's columns
    test_gui_logic       # GUI filter/sort/tag semantics, headless
    test_artifacts       # non-.pf artifacts match the manual byte-level analysis
    test_superfetch      # Ag*.db / .7db / .ebd: every path vouched for by its own hash
    test_readyboot       # PfB chunk chain decodes exactly; crafted chains are refused
    test_csv_escaping    # list-cell escaping survives hostile filenames
    test_cli_errors      # CLI fails usefully and never discards a run
    test_layering        # core stays Qt-free; frozen-build guards present
    test_memory          # memory per record stays bounded; lazy chains stay correct
    test_ads             # ADS recovery logic + the carrier-timestamp rule
    test_output_fidelity # every output surface matches the parsed record exactly
    test_byte_coverage   # the parser reads the whole file, not just the fields it names
    test_invariants      # properties that only a whole corpus can show: determinism, oracles
    test_windows_lane    # the Windows-only paths, exercised off Windows against stubs
    test_harness         # a suite that cannot run skips; it never passes vacuously
)

# A suite that could not run exits 77 (corpus.SKIP_EXIT). It is reported as SKIP and, crucially,
# never counted as a pass: an unrun suite proves nothing, which is the same rule the tool itself
# applies to an unscanned folder. The run as a whole then exits non-zero.
SKIP_EXIT=77

fail=0
skip=0
skipped_names=()
for s in "${SUITE[@]}"; do
    printf '%-22s ' "$s"
    out=$(timeout 900 python3 "$s.py" 2>&1)
    code=$?
    if [ "$code" -eq 0 ]; then
        echo "PASS"
    elif [ "$code" -eq "$SKIP_EXIT" ]; then
        echo "SKIP"
        echo "$out" | tail -6 | sed 's/^/    /'
        skip=$((skip + 1))
        skipped_names+=("$s")
    else
        echo "FAIL"
        echo "$out" | tail -20 | sed 's/^/    /'
        fail=$((fail + 1))
    fi
done

pass=$(( ${#SUITE[@]} - fail - skip ))
echo
if [ "$fail" -eq 0 ] && [ "$skip" -eq 0 ]; then
    echo "all ${#SUITE[@]} suites green"
    exit 0
fi

echo "$pass green, $skip skipped, $fail failed, of ${#SUITE[@]}"
if [ "$skip" -ne 0 ]; then
    echo "NOT a full pass - these did not run: ${skipped_names[*]}"
fi
[ "$fail" -ne 0 ] && exit "$fail"
exit "$SKIP_EXIT"
