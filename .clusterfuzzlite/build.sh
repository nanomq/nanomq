#!/bin/bash
set -euo pipefail

cd "$SRC/nanomq"

export CC="${CC:-clang}"
export CXX="${CXX:-clang++}"

rm -rf build
mkdir -p build
cd build

SAVED_LDFLAGS="${LDFLAGS:-}"
unset LDFLAGS

cmake .. \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DBUILD_STATIC_LIB=ON \
  -DENABLE_RULE_ENGINE=ON \
  -DENABLE_ACL=ON \
  -DENABLE_JWT=OFF \
  -DBUILD_NFTP=OFF \
  -DBUILD_NANOMQ_CLI=OFF \
  -DNANOMQ_TESTS=OFF

make -j"$(nproc)"

cd ..
LDFLAGS="${SAVED_LDFLAGS}"

FUZZ_DIR="fuzz"
DICT_FILE="$FUZZ_DIR/dict/pub_decode_fuzzer.dict"
LIBS=(
  build/nanomq/libnanomq.a
  build/nng/libnng.a
  -lm
)
INCLUDES=(
  -Inanomq
  -Inanomq/include
  -Inng/include
  -Inng/src
  -Inng/src/core
  -Inng/src/supplemental
)

build_target() {
  local src="$1"
  local target="$2"
  echo "Building fuzz target: $target"

  "$CC" \
    ${CFLAGS:-} \
    "$src" \
    "${INCLUDES[@]}" \
    -DSUPP_RULE_ENGINE \
    -DACL_SUPP \
    -DNNG_PLATFORM_POSIX \
    -DNNG_PLATFORM_LINUX \
    "${LIBS[@]}" \
    ${LIB_FUZZING_ENGINE:-} \
    ${LDFLAGS:-} \
    -o "$OUT/$target"
}

if [[ ! -f "$FUZZ_DIR/pub_decode_fuzzer.c" ]]; then
  echo "Missing $FUZZ_DIR/pub_decode_fuzzer.c"
  exit 1
fi

mapfile -t FUZZ_SRCS < <(find "$FUZZ_DIR" -maxdepth 1 -type f \( -name "fuzz_*.c" -o -name "pub_decode_fuzzer.c" \) \
  ! -name "fuzz_nng_url.c" \
  ! -name "fuzz_mqtt_common_decoder.c" \
  ! -name "fuzz_rule_sql.c" | sort)

if [[ "${#FUZZ_SRCS[@]}" -eq 0 ]]; then
  echo "No fuzz targets found in $FUZZ_DIR"
  exit 1
fi

for src in "${FUZZ_SRCS[@]}"; do
  target="$(basename "$src" .c)"
  build_target "$src" "$target"
done

for src in "${FUZZ_SRCS[@]}"; do
  target="$(basename "$src" .c)"
  corpus_dir="$FUZZ_DIR/corpus/$target"

  if [[ -d "$corpus_dir" ]]; then
    mkdir -p "$OUT/${target}_seed_corpus"
    cp -r "$corpus_dir/." "$OUT/${target}_seed_corpus/" 2>/dev/null || true
  fi
done

if [[ -f "$DICT_FILE" ]]; then
  cp "$DICT_FILE" "$OUT/pub_decode_fuzzer.dict"
fi

echo "NanoMQ fuzz build done"
