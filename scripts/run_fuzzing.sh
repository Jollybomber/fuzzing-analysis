#!/bin/bash
set -e

# Anchor project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

TARGET=$1
VARIANT=${2:-asan} # Default to asan if not specified (options: asan, asan_ubsan)
DURATION=7200    # 2 hours in seconds (AFL++ -V flag)

if [ -z "$TARGET" ]; then
    echo "[-] Error: No target specified."
    echo "Usage: $0 [cjson|jsonc] [asan|asan_ubsan]"
    exit 1
fi

# Set up binary and output paths based on target & variant
if [ "$TARGET" == "cjson" ]; then
    BIN_PATH="$PROJECT_ROOT/builds/cjson_afl_$VARIANT/cjson_parse"
    OUT_DIR="$PROJECT_ROOT/results/cjson_fuzz_out_$VARIANT"
elif [ "$TARGET" == "jsonc" ]; then
    BIN_PATH="$PROJECT_ROOT/builds/jsonc_afl_$VARIANT/build_internal/apps/json_parse"
    OUT_DIR="$PROJECT_ROOT/results/jsonc_fuzz_out_$VARIANT"
else
    echo "[-] Error: Invalid target '$TARGET'. Choose 'cjson' or 'jsonc'."
    exit 1
fi

# Verify binary exists
if [ ! -f "$BIN_PATH" ]; then
    echo "[-] Error: Instrumented binary not found at $BIN_PATH"
    echo "    Make sure you ran setup_and_build.sh successfully."
    exit 1
fi

# Verify seed directory exists
SEED_DIR="$PROJECT_ROOT/fuzz_seeds"
if [ ! -d "$SEED_DIR" ] || [ -z "$(ls -A "$SEED_DIR")" ]; then
    echo "[-] Error: Seed directory '$SEED_DIR' is missing or empty."
    exit 1
fi

echo "[+] Launching 2-hour AFL++ campaign for $TARGET ($VARIANT variant)..."
echo "[+] Results will be saved to: $OUT_DIR"

# Execute AFL++ with a 2-hour timeout (-V 7200)
afl-fuzz -i "$SEED_DIR" -o "$OUT_DIR" -V "$DURATION" -- "$BIN_PATH" @@
