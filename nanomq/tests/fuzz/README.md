# NanoMQ Fuzzing (Test Entry)

This directory keeps the CMake test entry for libFuzzer targets.
Canonical fuzz assets are managed under the top-level `fuzz/` directory.

## Canonical Paths

- Target source: `fuzz/pub_decode_fuzzer.c`
- Dictionary: `fuzz/dict/pub_decode_fuzzer.dict`
- Seed corpus: `fuzz/corpus/pub_decode_fuzzer/`

## Local Build

```bash
mkdir build && cd build
cmake -DENABLE_FUZZING=ON \
      -DCMAKE_C_COMPILER=clang \
      -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_C_FLAGS="-fsanitize=fuzzer-no-link,address -g" \
      -DCMAKE_CXX_FLAGS="-fsanitize=fuzzer-no-link,address -g" ..
make pub_decode_fuzzer -j$(nproc)
```

## Local Run

```bash
./nanomq/tests/fuzz/pub_decode_fuzzer \
  -dict=../fuzz/dict/pub_decode_fuzzer.dict \
  ../fuzz/corpus/pub_decode_fuzzer/
```
