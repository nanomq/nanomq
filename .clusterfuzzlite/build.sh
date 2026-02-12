#!/bin/bash -eu

################################
# 1. 基本环境
################################
# cd $SRC/nanomq

export CC=${CC:-clang}
export CXX=${CXX:-clang++}
CXXFLAGS="${CXXFLAGS:-}"
CXXFLAGS="${CXXFLAGS//-stdlib=libc++/}"
CXXFLAGS="${CXXFLAGS//-stdlib=libstdc++/}"
export CXXFLAGS="$CXXFLAGS -stdlib=libstdc++"

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
  -DENABLE_JWT=OFF \
  -DENABLE_PARQUET=ON

make -j$(nproc)

################################
# 3. 构建 fuzz targets
################################

cd ..

FUZZ_DIR=fuzz
LIBS=(
  build/nanomq/libnanomq.a
  build/nng/libnng.a
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
ARROW_PARQUET_LIBS="$(pkg-config --libs arrow parquet)"
ARROW_PARQUET_LIBS_STATIC="$(pkg-config --libs --static arrow parquet 2>/dev/null || true)"

EXTRA_LIBS="-lstdc++ $ARROW_PARQUET_LIBS -lssl -lcrypto"
STATIC_EXTRA_LIBS=""
if [ "${NANOMQ_FUZZ_STATIC_DEPS:-0}" = "1" ] && [ -n "$ARROW_PARQUET_LIBS_STATIC" ]; then
    STATIC_EXTRA_LIBS="-Wl,-Bstatic $ARROW_PARQUET_LIBS_STATIC -Wl,-Bdynamic -lstdc++ -lssl -lcrypto"
fi

for src in $FUZZ_DIR/fuzz_*.c; do
    target=$(basename "$src" .c)
    echo "Building fuzz target: $target"

    $CC $CFLAGS \
      -c $src \
      -fsanitize=fuzzer,address \
      ${INCLUDES[@]} \
      -o $target.o

    if [ -n "$STATIC_EXTRA_LIBS" ]; then
        set +e
        $CXX $CXXFLAGS \
          $target.o \
          ${LIBS[@]} \
          -fsanitize=fuzzer,address \
          $STATIC_EXTRA_LIBS \
          -Wl,-rpath,'$ORIGIN' \
          -o $OUT/$target
        rc=$?
        set -e
        if [ $rc -ne 0 ]; then
            echo "Static link failed for $target, falling back to dynamic deps."
            $CXX $CXXFLAGS \
              $target.o \
              ${LIBS[@]} \
              -fsanitize=fuzzer,address \
              $EXTRA_LIBS \
              -Wl,-rpath,'$ORIGIN' \
              -o $OUT/$target
        fi
    else
        $CXX $CXXFLAGS \
          $target.o \
          ${LIBS[@]} \
          -fsanitize=fuzzer,address \
          $EXTRA_LIBS \
          -Wl,-rpath,'$ORIGIN' \
          -o $OUT/$target
    fi

    rm -f $target.o
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

# Copy shared libraries to output directory
cp /usr/lib/x86_64-linux-gnu/libparquet.so* $OUT/
cp /usr/lib/x86_64-linux-gnu/libarrow.so* $OUT/
cp /usr/lib/x86_64-linux-gnu/libthrift* $OUT/
cp /usr/lib/x86_64-linux-gnu/libssl.so* $OUT/
cp /usr/lib/x86_64-linux-gnu/libcrypto.so* $OUT/
cp /usr/lib/x86_64-linux-gnu/libre2.so* $OUT/

copy_deps() {
    local bin="$1"
    if ! command -v ldd >/dev/null 2>&1; then
        return 0
    fi
    ldd "$bin" 2>/dev/null | awk '($2=="=>"){print $3} ($1 ~ /^\//){print $1}' | while read -r dep; do
        [ -f "$dep" ] || continue
        local base
        base="$(basename "$dep")"
        case "$base" in
            ld-linux*|libc.so*|libm.so*|libpthread.so*|librt.so*|libdl.so*|libgcc_s.so*|libstdc++.so*|libasan.so*|libubsan.so*|libtsan.so*|liblsan.so*|libclang_rt* )
                continue
                ;;
        esac
        cp -L "$dep" "$OUT/" 2>/dev/null || true
    done
}

if command -v ldconfig >/dev/null 2>&1; then
    ldconfig -p 2>/dev/null | awk '/libutf8proc\\.so/ {print $NF}' | while read -r lib; do
        cp -L "$lib" "$OUT/" 2>/dev/null || true
    done
fi

for f in "$OUT"/libarrow.so* "$OUT"/libparquet.so* "$OUT"/fuzz_*; do
    [ -e "$f" ] || continue
    copy_deps "$f"
done

# Patch RPATH for all shared libraries to find dependencies in $ORIGIN
if command -v patchelf >/dev/null 2>&1; then
    find $OUT -name "*.so*" -exec patchelf --set-rpath '$ORIGIN' {} \;
fi

echo "NanoMQ fuzz build done"
