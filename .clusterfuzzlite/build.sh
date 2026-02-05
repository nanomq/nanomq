#!/bin/bash -eu

################################
# 1. 基本环境
################################
# cd $SRC/nanomq

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
  -DBUILD_CLIENT=OFF \
  -DBUILD_NFTP=OFF \
  -DENABLE_RULE_ENGINE=ON \
  -DENABLE_ACL=ON \
  -DNANOMQ_TESTS=OFF \
  -DNNG_TESTS=OFF \
  -DENABLE_JWT=ON \
  -DNNG_ENABLE_PARQUET=ON

make -j$(nproc)

################################
# 3. 构建 fuzz targets
################################

cd ..

FUZZ_DIR=fuzz
LIBS=(
  build/nanomq/libnanomq.a
  build/nng/libnng.a
  build/extern/l8w8jwt/libl8w8jwt.a
  build/extern/l8w8jwt/mbedtls/library/libmbedtls.a
  build/extern/l8w8jwt/mbedtls/library/libmbedx509.a
  build/extern/l8w8jwt/mbedtls/library/libmbedcrypto.a
  build/nanomq_cli/nftp-codec/libnftp-codec-static.a
)

INCLUDES=(
  -Inanomq
  -Inanomq/include
  -Inng/include
  -Inng/src
  -Inng/src/core
  -Inng/src/supplemental
  -Iextern/l8w8jwt/include
  -Inanomq_cli/nftp-codec/src
  -DNNG_PLATFORM_POSIX
)

# Link with C++ standard library and Arrow/Parquet
EXTRA_LIBS="-lstdc++ $(pkg-config --libs arrow parquet) -lssl -lcrypto"

for src in $FUZZ_DIR/fuzz_*.c; do
    target=$(basename "$src" .c)
    echo "Building fuzz target: $target"

    $CC \
      $src \
      ${LIBS[@]} \
      -fsanitize=fuzzer,address \
      ${INCLUDES[@]} \
      $EXTRA_LIBS \
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
