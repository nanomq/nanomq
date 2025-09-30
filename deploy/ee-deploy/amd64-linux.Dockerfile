# syntax=docker/dockerfile:1
FROM wangha666/edge-amd64-linux-env-basic:1.0.0
ARG DASHBOARD_VER

WORKDIR /opt
COPY ../.. ./NanoMQ_mirror/

WORKDIR /opt/NanoMQ_mirror
RUN mkdir -p build
RUN rm -rf build/CMakeFiles build/CMakeCache.txt

WORKDIR /opt/NanoMQ_mirror/build
RUN cmake \
     -DENABLE_LICENSE_STD=ON -DBUILD_BENCH=ON \
     -DENABLE_DASHBOARD=ON -DDASHBOARD_VERSION=$DASHBOARD_VER -DGITHUB_TOKEN=$FETCH_TOKEN \
     -DNNG_ENABLE_QUIC=ON -DQUIC_BUILD_SHARED=OFF \
     -DENABLE_JWT=ON -DGEN_FILES=OFF -DNNG_ENABLE_SQLITE=ON \
     -DENABLE_RULE_ENGINE=ON -DBUILD_ZMQ_GATEWAY=ON \
     #-DOPENSSL_ROOT_DIR=/usr/local \
     -DNNG_ENABLE_TLS=ON .. && make -j8

