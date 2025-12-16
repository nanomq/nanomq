#!/bin/bash
set -ex

echo "==> Building NanoMQ fuzzers"

export CC=clang
export CXX=clang++

# Safe defaults
CFLAGS="${CFLAGS:-}"
CXXFLAGS="${CXXFLAGS:-}"
LDFLAGS="${LDFLAGS:-}"

# IMPORTANT:
# DO NOT link libFuzzer globally
export CFLAGS="${CFLAGS}"
export CXXFLAGS="${CXXFLAGS}"
export LDFLAGS="${LDFLAGS}"

mkdir -p build
cd build

cmake .. \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DENABLE_FUZZING=ON

make -j$(nproc)

cp fuzz_mqtt_packet /out/
