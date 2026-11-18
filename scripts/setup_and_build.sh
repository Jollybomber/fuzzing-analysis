#!/bin/bash
set -e

# Resolve paths from the script so reruns also work outside the project root.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"
BUILD_JOBS="${BUILD_JOBS:-$(getconf _NPROCESSORS_ONLN)}"

echo "[+] Setting up cJSON & json-c Fuzzing and Analysis Environment..."

# 1. Create directory structures (ignored by git)
mkdir -p builds/cjson_normal builds/cjson_afl_asan builds/cjson_afl_asan_ubsan
mkdir -p builds/jsonc_normal builds/jsonc_afl_asan builds/jsonc_afl_asan_ubsan
mkdir -p cjson_fuzz_out jsonc_fuzz_out

# ==========================================
# 2. Build cJSON Variants
# ==========================================
echo "[+] Compiling cJSON binaries..."

# Variant A: Normal Baseline
gcc -O3 -I./src/cjson_src ./scripts/cjson_parse.c ./src/cjson_src/cJSON.c -o ./builds/cjson_normal/cjson_parse

# Variant B: AFL++ with ASan only
export AFL_USE_ASAN=1
afl-clang-fast -O3 -fsanitize=address -fno-omit-frame-pointer \
  -I./src/cjson_src ./scripts/cjson_parse.c ./src/cjson_src/cJSON.c \
  -o ./builds/cjson_afl_asan/cjson_parse
unset AFL_USE_ASAN

# Variant C: AFL++ with ASan + UBSan
export AFL_USE_ASAN=1
afl-clang-fast -O3 -fsanitize=address,undefined -fno-omit-frame-pointer \
  -I./src/cjson_src ./scripts/cjson_parse.c ./src/cjson_src/cJSON.c \
  -o ./builds/cjson_afl_asan_ubsan/cjson_parse
unset AFL_USE_ASAN


# ==========================================
# 3. Build json-c Variants
# ==========================================
echo "[+] Compiling json-c binaries..."
# Variant A: Normal Baseline
cmake -S "$PROJECT_ROOT/src/jsonc_src" \
      -B "$PROJECT_ROOT/builds/jsonc_normal/build_internal" \
      -DCMAKE_C_COMPILER=gcc -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_STATIC_LIBS=ON -DDISABLE_WERROR=ON
cmake --build "$PROJECT_ROOT/builds/jsonc_normal/build_internal" --parallel "$BUILD_JOBS"
gcc -O3 -I"$PROJECT_ROOT/src/jsonc_src" -I"$PROJECT_ROOT/builds/jsonc_normal/build_internal" \
    "$PROJECT_ROOT/scripts/jsonc_parse.c" "$PROJECT_ROOT/builds/jsonc_normal/build_internal/libjson-c.a" \
    -o "$PROJECT_ROOT/builds/jsonc_normal/jsonc_parse"

# Variant B: AFL++ with ASan only
export AFL_USE_ASAN=1
cmake -S "$PROJECT_ROOT/src/jsonc_src" \
      -B "$PROJECT_ROOT/builds/jsonc_afl_asan/build_internal" \
      -DCMAKE_C_COMPILER=afl-clang-fast \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_STATIC_LIBS=ON -DDISABLE_WERROR=ON \
      -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer"
cmake --build "$PROJECT_ROOT/builds/jsonc_afl_asan/build_internal" --parallel "$BUILD_JOBS"
afl-clang-fast -O3 -fsanitize=address -fno-omit-frame-pointer \
    -I"$PROJECT_ROOT/src/jsonc_src" -I"$PROJECT_ROOT/builds/jsonc_afl_asan/build_internal" \
    "$PROJECT_ROOT/scripts/jsonc_parse.c" "$PROJECT_ROOT/builds/jsonc_afl_asan/build_internal/libjson-c.a" \
    -o "$PROJECT_ROOT/builds/jsonc_afl_asan/jsonc_parse"
unset AFL_USE_ASAN

# Variant C: AFL++ with ASan + UBSan
export AFL_USE_ASAN=1
cmake -S "$PROJECT_ROOT/src/jsonc_src" \
      -B "$PROJECT_ROOT/builds/jsonc_afl_asan_ubsan/build_internal" \
      -DCMAKE_C_COMPILER=afl-clang-fast \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_STATIC_LIBS=ON -DDISABLE_WERROR=ON \
      -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer"
cmake --build "$PROJECT_ROOT/builds/jsonc_afl_asan_ubsan/build_internal" --parallel "$BUILD_JOBS"
afl-clang-fast -O3 -fsanitize=address,undefined -fno-omit-frame-pointer \
    -I"$PROJECT_ROOT/src/jsonc_src" -I"$PROJECT_ROOT/builds/jsonc_afl_asan_ubsan/build_internal" \
    "$PROJECT_ROOT/scripts/jsonc_parse.c" "$PROJECT_ROOT/builds/jsonc_afl_asan_ubsan/build_internal/libjson-c.a" \
    -o "$PROJECT_ROOT/builds/jsonc_afl_asan_ubsan/jsonc_parse"
unset AFL_USE_ASAN

echo "[+] All three variants built successfully for both libraries!"
