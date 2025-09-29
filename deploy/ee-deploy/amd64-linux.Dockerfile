FROM edge-amd64-linux-env-basic:1.0.0

WORKDIR /opt
COPY ./NanoMQ_mirror/ ./NanoMQ_mirror/

WORKDIR /opt/NanoMQ_mirror
RUN mkdir build && cd build && cmake \
     -DENABLE_LICENSE_STD=ON \
     #-DOPENSSL_ROOT_DIR=/usr/local \
     #-DENABLE_DASHBOARD=ON -DDASHBOARD_VERSION=0.0.4 -DBUILD_BENCH=ON \
     -DNNG_ENABLE_QUIC=ON -DQUIC_BUILD_SHARED=OFF \
     -DENABLE_JWT=ON -DGEN_FILES=OFF -DNNG_ENABLE_SQLITE=ON \
     -DENABLE_RULE_ENGINE=ON -DBUILD_ZMQ_GATEWAY=ON \
     -DNNG_ENABLE_TLS=ON .. && make -j8

