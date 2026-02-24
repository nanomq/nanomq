# NanoMQ Fuzzing Infrastructure

This directory contains fuzzing targets for NanoMQ using LibFuzzer and ClusterFuzzLite.

## Fuzz Targets

### 1. fuzz_rule_sql.c
Fuzzes the rule engine SQL parser (`rule_sql_parse`).

**Target Areas:**
- SQL SELECT statement parsing
- Field extraction (payload, qos, topic, clientid, username, etc.)
- FROM clause parsing
- WHERE clause parsing with conditions
- Complex payload path parsing (e.g., `payload.x.y.z`)

**Corpus:** `corpus/fuzz_rule_sql/`

### 2. fuzz_mqtt_codec.c
Fuzzes MQTT packet encoding/decoding for both MQTT v3.1.1 and v5.

**Target Areas:**
- MQTT fixed header parsing
- Variable header parsing (CONNECT, PUBLISH, SUBSCRIBE, etc.)
- Property parsing (MQTT v5)
- Payload extraction
- Protocol version handling

**Corpus:** `corpus/fuzz_mqtt_codec/`

### 3. fuzz_hocon_parser.c
Fuzzes the HOCON configuration file parser.

**Target Areas:**
- HOCON syntax parsing
- Configuration object hierarchy
- Key-value pair extraction
- Nested object handling
- Array parsing
- Comments and formatting

**Corpus:** `corpus/fuzz_hocon_parser/`

### 4. fuzz_acl_parser.c
Fuzzes the ACL (Access Control List) rule JSON parser.

**Target Areas:**
- ACL rule JSON parsing
- Permission types (allow/deny)
- Action types (publish/subscribe/pubsub)
- Rule types (username, clientid, ipaddr)
- Complex rules (AND/OR logic)
- Topic pattern matching
- String and array value extraction

**Corpus:** `corpus/fuzz_acl_parser/`

### 5. fuzz_rest_api.c
Fuzzes the REST API JSON request processing.

**Target Areas:**
- JSON request parsing
- Object/array iteration
- Rule creation requests
- MQTT message requests
- Configuration update requests
- Parameter validation
- Response generation

**Corpus:** `corpus/fuzz_rest_api/`

### 6. fuzz_nftp.c
Fuzzes the NFTP (Nano File Transfer Protocol) codec.

**Target Areas:**
- NFTP packet decoding
- Header parsing
- Payload handling
- Protocol version checking

### 7. fuzz_jwt.c
Fuzzes the JWT (JSON Web Token) decoding and validation logic.

**Target Areas:**
- JWT token parsing
- Base64 decoding
- JSON payload parsing
- Signature verification (logic flow)
- Claim extraction

### 8. fuzz_nng_url.c
Fuzzes the nng URL parsing library (`nni_url_parse`).

**Target Areas:**
- URL scheme parsing
- Hostname and port extraction
- Userinfo (username/password) parsing
- Path and query string normalization
- Fragment handling

### 9. fuzz_nng_http.c
Fuzzes the nng HTTP request and response parser.

**Target Areas:**
- HTTP request line parsing (method, URI, version)
- HTTP response status line parsing (version, code, reason)
- Header parsing and extraction
- Entity body handling (chunked transfer encoding)

### 10. fuzz_topic_repub.c
Fuzzes the topic republication logic used in bridging.

**Target Areas:**
- Topic preprocessing (`preprocess_topics`)
- Topic republication generation (`generate_repub_topic`)
- Wildcard handling (+ and #)
- Topic level counting and skipping
- String manipulation safety

## Building Fuzz Targets

### Using ClusterFuzzLite

The fuzz targets are automatically built by ClusterFuzzLite using the build script:

```bash
.clusterfuzzlite/build.sh
```

This script:
1. Builds NanoMQ with static libraries
2. Enables RULE_ENGINE and ACL support
3. Compiles all fuzz_*.c files with LibFuzzer and AddressSanitizer
4. Deploys seed corpus for each target

### Manual Build (for local testing)

```bash
# Build NanoMQ with fuzzing support
mkdir -p build && cd build
cmake .. \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DBUILD_STATIC_LIB=ON \
  -DENABLE_RULE_ENGINE=ON \
  -DENABLE_ACL=ON \
  -DENABLE_JWT=ON \
  -DBUILD_NFTP=ON

make -j$(nproc)

# Build fuzz targets manually
cd ..
for target in fuzz/fuzz_*.c; do
    name=$(basename "$target" .c)
    clang \
      "$target" \
      build/nanomq/libnanomq.a \
      build/nng/libnng.a \
      -fsanitize=fuzzer,address,undefined \
      -Inanomq -Inanomq/include \
      -Inng/include -Inng/src/core -Inng/src/supplemental \
      -o "fuzz/$name"
done
```

## Running Fuzz Targets Locally

```bash
# Run a single target with corpus
./fuzz/fuzz_rule_sql fuzz/corpus/fuzz_rule_sql/ -max_total_time=60

# Run with multiple cores
./fuzz/fuzz_mqtt_codec fuzz/corpus/fuzz_mqtt_codec/ -jobs=4 -workers=4

# Generate coverage report
./fuzz/fuzz_acl_parser fuzz/corpus/fuzz_acl_parser/ \
  -print_coverage=1 -runs=10000
```

## Seed Corpus

Each fuzz target has a seed corpus directory containing valid input samples:

- **fuzz_rule_sql**: Valid SQL SELECT statements
- **fuzz_mqtt_codec**: Valid MQTT packets (binary format)
- **fuzz_hocon_parser**: Valid HOCON configuration snippets
- **fuzz_acl_parser**: Valid ACL rule JSON objects
- **fuzz_rest_api**: Valid REST API request JSON objects

## Adding New Fuzz Targets

1. Create a new `fuzz_<name>.c` file in this directory
2. Implement `LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`
3. Add seed corpus to `corpus/fuzz_<name>/`
4. The build script will automatically detect and build the new target

## Best Practices

1. **Input Validation**: Always validate size bounds before processing
2. **Memory Management**: Always free allocated memory to avoid leaks
3. **Null Checks**: Check for NULL returns from allocation functions
4. **Corpus Quality**: Provide diverse, valid seed inputs for better coverage
5. **Cleanup**: Always cleanup resources (close files, free memory, etc.)

## Integration with CI/CD

This fuzzing infrastructure integrates with:
- ClusterFuzzLite for continuous fuzzing
- GitHub Actions for automated testing
- OSS-Fuzz compatible for potential inclusion

## Troubleshooting

### Build Failures

If compilation fails, ensure:
- Clang is installed (`clang --version`)
- All dependencies are built (`make -j$(nproc)` in build/)
- Include paths are correct for your NanoMQ version

### Runtime Crashes

If fuzzer crashes immediately:
- Check if libraries are compatible (rebuild everything)
- Verify sanitizer flags are consistent
- Test with a known-good corpus input

### Low Coverage

If coverage is low:
- Add more diverse seed inputs
- Review code paths not covered
- Consider adding focused fuzz targets

## Resources

- [LibFuzzer Documentation](https://llvm.org/docs/LibFuzzer.html)
- [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/)
- [OSS-Fuzz](https://github.com/google/oss-fuzz)
