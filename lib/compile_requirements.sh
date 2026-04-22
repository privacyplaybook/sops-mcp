#!/bin/bash
# Regenerate all requirements.lock.txt files with pinned versions and hashes.
# Requires: pip install pip-tools
#
# Run this from the repository root whenever you update a .in file.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

IN_FILES=(
    "requirements.in"
)

failed=0
for infile in "${IN_FILES[@]}"; do
    outfile="${infile%.in}.lock.txt"
    echo "Compiling $infile -> $outfile"
    if ! pip-compile --generate-hashes --strip-extras --allow-unsafe \
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
