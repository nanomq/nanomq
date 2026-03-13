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
# 添加 SUPP_PARQUET 以支持 parquet
NANOMQ_FLAGS="-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DSUPP_RULE_ENGINE -DACL_SUPP -DENABLE_LOG -DSUPP_SYSLOG -DSUPP_PARQUET"

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

# 启用 Parquet，禁用 JWT
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

# 使用 pkg-config 获取 arrow/parquet 依赖
# 动态获取 libdir
PARQUET_LIBDIR=$(pkg-config --variable=libdir parquet)
if [ -z "$PARQUET_LIBDIR" ]; then PARQUET_LIBDIR="/usr/local/lib"; fi

ARROW_LIBDIR=$(pkg-config --variable=libdir arrow)
if [ -z "$ARROW_LIBDIR" ]; then ARROW_LIBDIR="/usr/local/lib"; fi

# 优先使用静态库
if [ -f "$PARQUET_LIBDIR/libparquet.a" ]; then
    PARQUET_LINK="$PARQUET_LIBDIR/libparquet.a"
else
    PARQUET_LINK="-lparquet"
fi

if [ -f "$ARROW_LIBDIR/libarrow.a" ]; then
    ARROW_LINK="$ARROW_LIBDIR/libarrow.a"
else
    ARROW_LINK="-larrow"
fi

# 获取其他依赖，过滤掉 -lparquet -larrow 和 _bundled_dependencies 以及 CI 环境缺失的 transitive deps
# 同时过滤掉 -lthrift, -lsnappy, -lz, -llz4, -lzstd, -lbrotli*, libbz2.so，改为手动链接静态库
# 同时过滤掉 -lre2, -lutf8proc, -lcurl，改为手动链接静态库
# 注意：必须先过滤 -lzstd 再过滤 -lz，否则 -lz 会匹配到 -lzstd 中的 -lz，导致留下 "std"
OTHER_LIBS=$(pkg-config --libs --static arrow parquet | sed -e 's/-lparquet//g' -e 's/-larrow//g' -e 's/_bundled_dependencies//g' -e 's/-lnghttp2//g' -e 's/-lidn2//g' -e 's/-lrtmp//g' -e 's/-lssh//g' -e 's/-lpsl//g' -e 's/-lgssapi_krb5//g' -e 's/-lkrb5//g' -e 's/-lk5crypto//g' -e 's/-lcom_err//g' -e 's/-llber//g' -e 's/-lldap//g' -e 's/-lthrift//g' -e 's/-lsnappy//g' -e 's/-lzstd//g' -e 's/-lz//g' -e 's/-llz4//g' -e 's/-lbrotlidec//g' -e 's/-lbrotlienc//g' -e 's/-lbrotlicommon//g' -e 's/-lre2//g' -e 's/-lutf8proc//g' -e 's/-lcurl//g' -e 's|/[^ ]*libbz2.so||g')

# 检查是否需要链接 mimalloc (CI 环境 Arrow 可能依赖它)
# 强制添加 -lmimalloc，因为 Arrow 静态库通常依赖它，且我们在 Dockerfile 中安装了 libmimalloc-dev
# 强制添加 -l:libthrift.a 以避免动态链接 libthrift.so (解决 CI 运行时找不到 libthrift-0.13.0.so 的问题)
# 强制添加其他压缩库的静态链接，避免动态链接导致运行时找不到库
# 强制添加 re2, utf8proc, curl 的静态链接
OTHER_LIBS="-lmimalloc -l:libthrift.a -l:libsnappy.a -l:libz.a -l:liblz4.a -l:libzstd.a -l:libbrotlidec.a -l:libbrotlienc.a -l:libbrotlicommon.a -l:libbz2.a -l:libre2.a -l:libutf8proc.a -l:libcurl.a $OTHER_LIBS"

PARQUET_LIBS="$PARQUET_LINK $ARROW_LINK $OTHER_LIBS"

# 使用 OpenSSL 作为基础依赖，并加上 Parquet 依赖
# 注意链接顺序：依赖库必须放在被依赖库之后
# NanoMQ -> Parquet/Arrow -> Thrift -> OpenSSL
BASE_EXTRA_LIBS="-lstdc++ $PARQUET_LIBS -lssl -lcrypto"

echo "Compiling fuzz targets with CFLAGS: $CFLAGS"

# 遍历需要编译的 fuzz targets
for file in $FUZZ_DIR/fuzz_rest_api_detailed.c $FUZZ_DIR/fuzz_exchang_server.c $FUZZ_DIR/fuzz_exchange.c $FUZZ_DIR/fuzz_parquet.c; do
    if [ ! -f "$file" ]; then
        echo "Skipping missing file: $file"
        continue
    fi

    src=$file
    target=$(basename $file .c)

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
