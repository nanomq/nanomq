## Perf in PATH(nanomq/build)

1. sudo perf record -g ./nanomq/nanomq broker start 'tcp://localhost:1883'

2. sudo perf script -i ../nanomq/build/perf.data > perf.unfold

## FlameGraph Create

1. git clone https://github.com/brendangregg/FlameGraph

2. ./stackcollapse-perf.pl perf.unfold > perf.folded

3. ./flamegraph.pl --flamechart perf.folded > perf.xml

