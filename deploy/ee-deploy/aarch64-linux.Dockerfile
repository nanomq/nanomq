# syntax=docker/dockerfile:1
FROM wangha666/edge-aarch64-linux-env-basic:1.0.0
ARG DASHBOARD_VER

WORKDIR /opt
COPY ../.. ./NanoMQ_mirror/

WORKDIR /opt/NanoMQ_mirror
RUN mkdir build

WORKDIR /opt/NanoMQ_mirror/build
RUN --mount=type=secret,id=fetch_token,env=FETCH_TOKEN cmake \
    -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc \
    -DCMAKE_CXX_COMPILER=aarch64-linux-gnu-g++ \
    -DCMAKE_TARGET_ARCHITECTURE=arm64 \
    -DGNU_MACHINE=aarch64-linux-gnu \
    -DCMAKE_CROSSCOMPILING=ON \
    -DONEBRANCH=1 \
	-DCMAKE_PREFIX_PATH=/usr/aarch64-linux-gnu \
    toolchains /opt/NanoMQ_mirror/nng/extern/msquic/cmake/toolchains/aarch64-linux.cmake \
    -DENABLE_LICENSE_STD=ON \
    -DBUILD_BENCH=ON \
    -DOPENSSL_ROOT_DIR=/usr/aarch64-linux-gnu \
    -DENABLE_DASHBOARD=ON -DDASHBOARD_VERSION=$DASHBOARD_VER -DGITHUB_TOKEN="$FETCH_TOKEN" \
    -DNNG_ENABLE_QUIC=ON -DQUIC_BUILD_SHARED=OFF \
    -DENABLE_JWT=ON -DGEN_FILES=OFF -DNNG_ENABLE_SQLITE=ON \
    -DENABLE_RULE_ENGINE=ON -DBUILD_ZMQ_GATEWAY=ON \
    -DNNG_ENABLE_TLS=ON .. && make -j8

