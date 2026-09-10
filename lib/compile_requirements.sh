#!/bin/bash
# Regenerate all requirements.lock.txt files with pinned versions and hashes.
# Requires: pip install pip-tools
#
# Run this from the repository root whenever you update a .in file.
#
#   lib/compile_requirements.sh              # resolve new requirements only
#   lib/compile_requirements.sh --upgrade    # also move existing pins forward
#
# Without --upgrade, pip-compile keeps every pin it already finds in the
# lockfile. That is what let cryptography and mcp sit on versions with
# published advisories through several regenerations: nothing in the .in
# file changed, so nothing moved. Reach for --upgrade when the audit
# reports a vulnerability.
set -euo pipefail

UPGRADE=()
if [ "${1:-}" = "--upgrade" ] || [ "${1:-}" = "-U" ]; then
    UPGRADE=(--upgrade)
    echo "Upgrading existing pins to the latest compatible versions."
fi

cd "$(git rev-parse --show-toplevel)"

IN_FILES=(
    "requirements.in"
)

failed=0
for infile in "${IN_FILES[@]}"; do
    outfile="${infile%.in}.lock.txt"
    echo "Compiling $infile -> $outfile"
    if ! pip-compile --generate-hashes --strip-extras --allow-unsafe \
        "${UPGRADE[@]+"${UPGRADE[@]}"}" \
        --output-file "$outfile" \
        "$infile"; then
        echo "ERROR: Failed to compile $infile"
        failed=1
    fi
done

if [ "$failed" -ne 0 ]; then
    echo "Some lockfiles failed to generate."
    exit 1
fi

echo "All lockfiles generated successfully."
