# NanoMQ Fuzzing

This directory is the canonical home for NanoMQ fuzz targets and seed corpus.
It consolidates branch fuzz work with the `pub_decode_fuzzer` integration introduced by PR #2238.

## Targets

The build script automatically compiles:

- `fuzz_*.c` targets under `fuzz/`
- `pub_decode_fuzzer.c` (focused on `decode_pub_message`)

Current targets include:

- `fuzz_acl_parser`
- `fuzz_base64`
- `fuzz_mqtt_codec`
- `fuzz_mqtt_common_decoder`
- `fuzz_mqtt_db`
- `fuzz_nng_http`
- `fuzz_nng_url`
- `fuzz_pub_handler`
- `fuzz_rest_api`
- `fuzz_rule_sql`
- `fuzz_sub_handler`
- `fuzz_topic_repub`
- `fuzz_unsub_handler`
- `pub_decode_fuzzer`

## PR #2238 Assets

- Source: `fuzz/pub_decode_fuzzer.c`
- Seed corpus: `fuzz/corpus/pub_decode_fuzzer/`
- Dictionary: `fuzz/dict/pub_decode_fuzzer.dict` (MQTT token dictionary)

## Build With ClusterFuzzLite

```bash
.clusterfuzzlite/build.sh
```

The script:

1. Builds NanoMQ static libraries.
2. Compiles all targets with OSS-Fuzz/ClusterFuzzLite-provided fuzzing flags.
3. Exports per-target seed corpus into `$OUT/*_seed_corpus`.
4. Exports `pub_decode_fuzzer` dictionary to `$OUT/pub_decode_fuzzer.dict`.

## Local Smoke Run

```bash
./build/nanomq/tests/fuzz/pub_decode_fuzzer \
  -dict=./fuzz/dict/pub_decode_fuzzer.dict \
  ./fuzz/corpus/pub_decode_fuzzer/
```
