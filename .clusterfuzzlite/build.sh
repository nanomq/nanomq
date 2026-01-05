#!/bin/bash -eu

################################
# 1. 基本环境
################################
cd $SRC/nanomq

export CC=${CC:-clang}
export CXX=${CXX:-clang++}

# OSS-Fuzz 自动注入：
# -fsanitize=fuzzer,address,undefined
# -O1 -g
# 不要手动再加 sanitizer

################################
# 2. 构建 NanoMQ（仅需要库）
################################

mkdir -p build
cd build

cmake .. \
  -DCMAKE_C_COMPILER=$CC \
  -DCMAKE_CXX_COMPILER=$CXX \
  -DBUILD_STATIC_LIB=ON \
  -DENABLE_RULE_ENGINE=ON \
  -DNANOMQ_TESTS=OFF

make -j$(nproc)

################################
# 3. 构建 fuzz targets
################################

cd ..

FUZZ_DIR=fuzz
LIBS=(
  build/nanomq/libnanomq.a
)

for src in $FUZZ_DIR/fuzz_*.c; do
    target=$(basename "$src" .c)
    echo "Building fuzz target: $target"

    $CC \
      $src \
      ${LIBS[@]} \
      -Iinclude \
      -Inng/include \
      -Inanomq \
      -Inanomq/include \
      -o $OUT/$target
done

################################
# 4. Seed corpus
################################

for src in $FUZZ_DIR/fuzz_*.c; do
    target=$(basename "$src" .c)
    corpus_dir="$FUZZ_DIR/corpus/$target"

    if [ -d "$corpus_dir" ]; then
        mkdir -p "$OUT/${target}_seed_corpus"
        cp "$corpus_dir"/* "$OUT/${target}_seed_corpus/" \
           2>/dev/null || true
    fi
done

echo "NanoMQ fuzz build done"
