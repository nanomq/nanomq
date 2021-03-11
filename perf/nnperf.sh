#!/bin/bash

# before running nnperf, perf & FlameGraph should be install
# FlameGraph < https://github.com/brendangregg/FlameGraph >
# you should run perf record and generate a perf.data

# argv1: path to perf.data
# argv2: path to stackcollapse-perf.pl
# argv3: path to flamegraph.pl

if [ $# -eq 4 ]
then
  echo "Example CMD: ./nnperf.sh A/perf.data B/stackcollapse-perf.pl B/flamegraph.pl";
fi

echo "Progress start .."
sudo -S bash -c "perf script -i $1 > perf.unfold";
echo "Progress 1/3 .."
$2 perf.unfold > perf.folded;
echo "Progress 2/3 .."
$3 --flamechart perf.folded > perf.xml;
echo "Progress 3/3 .."

rm -f ./perf.folded ./perf.unfold

# test in my PC:
# 1. sudo perf record -g ../build/nanomq/nanomq broker start 'tcp://localhost:1883'
# 2. ./nnperf.sh ../build/perf.data ../../FlameGraph/stackcollapse-perf.pl ../../FlameGraph/flamegraph.pl
