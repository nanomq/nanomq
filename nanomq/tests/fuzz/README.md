# NanoMQ Fuzzing

This directory contains libFuzzer-based fuzzers for NanoMQ. These tools are designed to be integrated into [OSS-Fuzz](https://github.com/google/oss-fuzz).

## Building the Fuzzers

To build the fuzzers, you must use a compiler with libFuzzer support (like Clang) and enable the `ENABLE_FUZZING` CMake option. It is highly recommended to enable AddressSanitizer (ASAN) to catch memory errors.

```bash
mkdir build && cd build
cmake -DENABLE_FUZZING=ON \
      -DCMAKE_C_COMPILER=clang \
      -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_C_FLAGS="-fsanitize=fuzzer-no-link,address -g" \
      -DCMAKE_CXX_FLAGS="-fsanitize=fuzzer-no-link,address -g" ..
make pub_decode_fuzzer -j$(nproc)
```

## Running the Fuzzers

The fuzzer binaries are located in the `build/nanomq/tests/fuzz/` directory.

### MQTT PUBLISH Decoder Fuzzer

To run the PUBLISH decoder fuzzer with the provided dictionary and corpus, run the following from the root of the `build` directory:

```bash
./nanomq/tests/fuzz/pub_decode_fuzzer \
  -dict=../nanomq/tests/fuzz/mqtt.dict \
  ../nanomq/tests/fuzz/corpus/
```

## Initial Findings (Reproducing Bugs)

The following issues were identified during initial fuzzing and have been fixed in this PR:

1. **Memory Leak**: Detected a leak in `free_pub_packet` where MQTT v5 properties for `PUBACK/REC/REL/COMP` packets were not correctly freed.
2. **Heap Buffer Overflow**: Identified a heap-buffer-overflow in `decode_pub_message` (line 2132) when processing truncated packets with QoS > 0.
