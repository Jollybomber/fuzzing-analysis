#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS_DIR="${ROOT_DIR}/scripts"
BUILD_DIR="${BUILD_DIR:-${ROOT_DIR}/build}"
BIN_DIR="${BIN_DIR:-${ROOT_DIR}/bin}"
BUILD_JOBS="${BUILD_JOBS:-$(getconf _NPROCESSORS_ONLN)}"
COMMON_FLAGS=(-O1 -g -fno-omit-frame-pointer)

# Adjust these paths if your cloned parser directories live elsewhere
CJSON_SRC="${CJSON_SRC:-${ROOT_DIR}/src/cjson_src}"
JSONC_SRC="${JSONC_SRC:-${ROOT_DIR}/src/jsonc_src}"

# Enforce common Clang toolchain
export CC=clang
export CXX=clang++
export AFL_CC=clang
export AFL_CXX=clang++

die() { echo "Error: $*" >&2; exit 1; }
[[ "$BUILD_JOBS" =~ ^[1-9][0-9]*$ ]] || die "BUILD_JOBS must be a positive integer"
for tool in clang clang++ afl-clang-fast cmake nm python3; do
    command -v "$tool" >/dev/null || die "Missing tool: $tool (run inside the AFL++ Linux container)"
done
[[ -f "$CJSON_SRC/cJSON.c" && -f "$JSONC_SRC/CMakeLists.txt" ]] || die "Parser sources are missing"
for directory in "$BUILD_DIR" "$BIN_DIR"; do
    [[ ! -e "$directory" ]] || die "Output already exists: $directory. Set BUILD_DIR and BIN_DIR to fresh paths."
done
mkdir -p "${BUILD_DIR}" "${BIN_DIR}"
BUILD_DIR="$(cd "$BUILD_DIR" && pwd)"
BIN_DIR="$(cd "$BIN_DIR" && pwd)"
exec > >(tee "$BUILD_DIR/build.log") 2>&1
cp "$SCRIPTS_DIR/setup_and_build.sh" "$SCRIPTS_DIR/cjson_parse.c" "$SCRIPTS_DIR/jsonc_parse.c" "$BUILD_DIR/"
echo "=== Toolchain Verification ==="
clang --version
afl-clang-fast --version
echo "Common flags for all variants: ${COMMON_FLAGS[*]}"

# AFL checks variable presence; a value of 0 still enables the sanitizer.
# Apply the same environment while compiling libraries, wrappers, and linking.
with_sanitizers() (
    local variant="$1"
    shift
    unset AFL_USE_ASAN AFL_USE_UBSAN AFL_USE_MSAN AFL_USE_LSAN AFL_USE_TSAN
    unset AFL_USE_CFISAN AFL_USE_RTSAN AFL_USE_TYSAN AFL_HARDEN
    case "$variant" in
        baseline|normal) ;;
        asan) export AFL_USE_ASAN=1 ;;
        asan_ubsan) export AFL_USE_ASAN=1 AFL_USE_UBSAN=1 ;;
        *) die "Unknown variant: $variant" ;;
    esac
    "$@"
)

# ------------------------------------------------------------------------------
# Helper: Build json-c static library in an isolated CMake directory
# ------------------------------------------------------------------------------
build_jsonc_lib() {
    local variant="$1"
    local compiler="$2"
    local vbuild="${BUILD_DIR}/jsonc_${variant}"
    cmake -S "${JSONC_SRC}" -B "${vbuild}" \
            -DCMAKE_C_COMPILER="${compiler}" \
            -DCMAKE_BUILD_TYPE= \
            -DCMAKE_C_FLAGS="${COMMON_FLAGS[*]}" \
            -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
            -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON \
            -DBUILD_TESTING=OFF \
            -DDISABLE_WERROR=ON
    cmake --build "${vbuild}" --target json-c --parallel "$BUILD_JOBS"
}

verify_objects() {
    local variant="$1" parser="$2" library="$3" wrapper="$4" symbols
    # Runtime code bundled in executables can contain UBSan symbols even without
    # UBSan target checks. Inspect unresolved references in target objects instead.
    symbols="$(nm -u "$library" "$wrapper")"
    printf '%s\n' "$symbols" > "$BUILD_DIR/${parser}_${variant}_symbols.txt"
    case "$variant" in
        baseline|normal)
            [[ "$symbols" != *'__asan_'* && "$symbols" != *'__ubsan_'* ]] || die "$parser/$variant unexpectedly contains sanitizer checks"
            ;;
        asan)
            [[ "$symbols" == *'__asan_'* && "$symbols" != *'__ubsan_'* ]] || die "$parser/$variant does not have ASan-only checks"
            ;;
        asan_ubsan)
            [[ "$symbols" == *'__asan_'* && "$symbols" == *'__ubsan_'* ]] || die "$parser/$variant is missing sanitizer checks"
            ;;
    esac
    if [[ "$variant" != baseline ]]; then
        [[ "$symbols" == *'__afl_'* ]] || die "$parser/$variant is missing AFL instrumentation"
    fi
    echo "Verified object instrumentation: $parser/$variant"
}

build_variant() {
    local variant="$1" compiler=afl-clang-fast suffix="afl_$1"
    local cbuild="$BUILD_DIR/cjson_$variant" jbuild="$BUILD_DIR/jsonc_$variant"
    if [[ "$variant" == baseline ]]; then compiler=clang; suffix=parse; fi
    mkdir -p "$cbuild"
    echo "=== Building $variant ==="
    "$compiler" "${COMMON_FLAGS[@]}" -I"$CJSON_SRC" -c "$CJSON_SRC/cJSON.c" -o "$cbuild/cJSON.o"
    "$compiler" "${COMMON_FLAGS[@]}" -Wall -Wextra -I"$CJSON_SRC" \
        -c "$SCRIPTS_DIR/cjson_parse.c" -o "$cbuild/wrapper.o"
    "$compiler" "${COMMON_FLAGS[@]}" "$cbuild/wrapper.o" "$cbuild/cJSON.o" -lm -o "$BIN_DIR/cjson_$suffix"

    build_jsonc_lib "$variant" "$compiler"
    "$compiler" "${COMMON_FLAGS[@]}" -Wall -Wextra -I"$JSONC_SRC" -I"$jbuild" \
        -c "$SCRIPTS_DIR/jsonc_parse.c" -o "$jbuild/wrapper.o"
    "$compiler" "${COMMON_FLAGS[@]}" "$jbuild/wrapper.o" "$jbuild/libjson-c.a" -o "$BIN_DIR/jsonc_$suffix"

    verify_objects "$variant" cjson "$cbuild/cJSON.o" "$cbuild/wrapper.o"
    verify_objects "$variant" jsonc "$jbuild/libjson-c.a" "$jbuild/wrapper.o"
}

for variant in baseline normal asan asan_ubsan; do
    with_sanitizers "$variant" build_variant "$variant"
done

echo "=== Smoke tests and build manifest ==="
python3 - "$BIN_DIR" "$BUILD_DIR" "$CJSON_SRC" "$JSONC_SRC" "${COMMON_FLAGS[*]}" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

bin_dir, build_dir, cjson_src, jsonc_src = map(Path, sys.argv[1:5])
env = dict(os.environ, ASAN_OPTIONS='abort_on_error=1:detect_leaks=0:symbolize=1',
           UBSAN_OPTIONS='halt_on_error=1:abort_on_error=1:symbolize=1')
targets = {}
with tempfile.TemporaryDirectory(dir=build_dir, prefix='smoke_') as temp:
    case = Path(temp) / 'input.json'
    for binary in sorted(bin_dir.iterdir()):
        for raw, expected in [(b'{"ok":true}', {'ok': True}), (b'null', None), (b'123', 123)]:
            case.write_bytes(raw)
            result = subprocess.run([str(binary), str(case)], capture_output=True, env=env, timeout=10)
            if result.returncode or result.stderr or json.loads(result.stdout) != expected:
                raise SystemExit(f'Smoke test failed: {binary.name}: {result}')
        case.write_bytes(b'{"ok":')
        result = subprocess.run([str(binary), str(case)], capture_output=True, env=env, timeout=10)
        if result.returncode != 1 or not result.stderr.startswith(b'Parse error') or result.stdout:
            raise SystemExit(f'Rejection test failed: {binary.name}: {result}')
        targets[binary.name] = hashlib.sha256(binary.read_bytes()).hexdigest()
        print(f'  PASS: {binary.name} (object, null, number, malformed input)')

def git_info(path):
    def git(*args):
        p = subprocess.run(['git', '-C', str(path), *args], capture_output=True, text=True)
        return p.stdout.strip() if p.returncode == 0 else None
    return {'commit': git('rev-parse', 'HEAD'), 'status': git('status', '--porcelain'),
            'tracked_diff': git('diff', 'HEAD')}

manifest = {
    'built_utc': datetime.now(timezone.utc).isoformat(),
    'common_flags': sys.argv[5], 'build_dir': str(build_dir),
    'clang_version': subprocess.check_output(['clang', '--version'], text=True),
    'afl_compiler_version': subprocess.check_output(['afl-clang-fast', '--version'], text=True, stderr=subprocess.STDOUT),
    'sanitizers': {'baseline': [], 'normal': [], 'asan': ['address'], 'asan_ubsan': ['address', 'undefined']},
    'binaries_sha256': targets,
    'source_repositories': {'cjson': git_info(cjson_src), 'jsonc': git_info(jsonc_src)},
    'build_inputs_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in (build_dir / 'setup_and_build.sh', build_dir / 'cjson_parse.c',
                                     build_dir / 'jsonc_parse.c', cjson_src / 'cJSON.c')},
    'object_instrumentation_verified': True, 'smoke_tests_passed': True,
}
(bin_dir / 'build_manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
PY
echo "Build verified. Targets: $BIN_DIR; logs and object checks: $BUILD_DIR"
