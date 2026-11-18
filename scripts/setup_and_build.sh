#!/bin/bash
set -e

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
mkdir -p builds/jsonc_normal/build_internal && cd builds/jsonc_normal/build_internal
cmake -DCMAKE_C_COMPILER=gcc -DCMAKE_BUILD_TYPE=Release ../../../src/jsonc_src
make -j$(nproc) && cd ../../..

# Variant B: AFL++ with ASan only
mkdir -p builds/jsonc_afl_asan/build_internal && cd builds/jsonc_afl_asan/build_internal
export AFL_USE_ASAN=1
cmake -DCMAKE_C_COMPILER=afl-clang-fast \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer" \
      ../../../src/jsonc_src
make -j$(nproc) && cd ../../..
unset AFL_USE_ASAN

# Variant C: AFL++ with ASan + UBSan
mkdir -p builds/jsonc_afl_asan_ubsan/build_internal && cd builds/jsonc_afl_asan_ubsan/build_internal
export AFL_USE_ASAN=1
cmake -DCMAKE_C_COMPILER=afl-clang-fast \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
      ../../../src/jsonc_src
make -j$(nproc) && cd ../../..
unset AFL_USE_ASAN

echo "[+] All three variants built successfully for both libraries!"