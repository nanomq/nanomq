#!/bin/bash -eu
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# 1. 设置编译器和编译选项
export CC=${CC:-clang}
export CXX=${CXX:-clang++}

# NanoMQ 需要的宏定义，确保 conf 结构体布局一致
# 必须与 build/nanomq/libnanomq.a 编译时的定义一致
NANOMQ_FLAGS="-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DSUPP_RULE_ENGINE -DACL_SUPP -DENABLE_LOG -DSUPP_SYSLOG"

# 分离 CFLAGS/CXXFLAGS，避免将 sanitizer 标志传递给不支持的检查
export CFLAGS="${CFLAGS:- -g -O1 -fsanitize=address,undefined} $NANOMQ_FLAGS"
export CXXFLAGS="${CXXFLAGS:- -g -O1 -fsanitize=address,undefined} $NANOMQ_FLAGS"
# 移除不支持的 stdlib 标志
CXXFLAGS="${CXXFLAGS//-stdlib=libc++/}"
CXXFLAGS="${CXXFLAGS//-stdlib=libstdc++/}"
export CXXFLAGS="$CXXFLAGS -stdlib=libstdc++"

export TMPDIR="${TMPDIR:-$PWD/build-tmp}"
mkdir -p "$TMPDIR"

export OUT="${OUT:-$PWD/build/fuzz}"
mkdir -p "$OUT"

# OSS-Fuzz 自动注入：
# -fsanitize=fuzzer,address,undefined
# -O1 -g
# 不要手动再加 sanitizer

################################
# 2. 构建 NanoMQ（仅需要库）
################################

# 使用 build 目录
mkdir -p build
cd build

# 禁用 JWT 和 Parquet 以避免依赖问题
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
  -DENABLE_PARQUET=OFF

make -j$(nproc)

################################
# 3. 构建 fuzz targets
################################

cd ..

FUZZ_DIR=fuzz
LIBS_BASE=(
  build/nanomq/libnanomq.a
  build/nng/libnng.a
)

INCLUDES=(
  -I.
  -Inanomq
  -Inanomq/include
  -Inng/include
  -Inng/src
  -Inng/src/core
  -Inng/src/supplemental
  -DNNG_PLATFORM_POSIX
)

# 使用 OpenSSL 作为基础依赖
BASE_EXTRA_LIBS="-lstdc++ -lssl -lcrypto"

echo "Compiling fuzz targets with CFLAGS: $CFLAGS"

for file in $FUZZ_DIR/fuzz_rest_api_detailed.c; do
    src=$file
    target=$(basename $file .c)

    # Skip parquet targets if not supported
    if [[ "$target" == *parquet* ]]; then
        continue
    fi

    # Special handling for different targets if needed
    TARGET_EXTRA_LIBS="$BASE_EXTRA_LIBS"

    $CC ${CFLAGS:-} \
      -c $src \
      -fsanitize=fuzzer,address \
      ${INCLUDES[@]} \
      -o $target.o

    $CXX ${CXXFLAGS:-} \
      $target.o \
      ${LIBS_BASE[@]} \
      -fsanitize=fuzzer,address \
      $TARGET_EXTRA_LIBS \
      -Wl,-rpath,'$ORIGIN' \
      -o $OUT/$target

    rm -f $target.o
done
