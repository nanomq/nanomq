FROM xuesengxinyi/parquet-compile:ubuntu18.04

RUN apt-get update && apt-get install -y git

WORKDIR /opt
RUN rm -rf mbedtls && git clone https://github.com/Mbed-TLS/mbedtls.git && \
     cd mbedtls && mkdir build_android && cd build_android && \
     git checkout v3.6.2 && \
     cmake -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc \
     -DCMAKE_CXX_COMPILER=aarch64-linux-gnu-g++ \
     -DENABLE_TESTING=OFF \
     -DCMAKE_FIND_ROOT_PATH=/usr/lib/aarch64-linux-gnu/\
     -DCMAKE_INSTALL_PREFIX=/usr/lib/aarch64-linux-gnu/ .. &&\
     make -j32 &&  make install

# COPY NanoMQ_mirror 源代码
WORKDIR /opt
COPY ../.. ./NanoMQ_mirror/

# 编译 nanomq
WORKDIR /opt/NanoMQ_mirror
RUN mkdir build && cd build && cmake \
     -DENABLE_PARQUET=ON  \
     -DBUILD_STATIC=OFF \
     -DNNG_ENABLE_TLS=ON \
     -DENABLE_FILETRANSFER=ON \
     -DNNG_TESTS=OFF .. && make -j8 && make install

RUN mkdir build-debug && cd build-debug && cmake \
    -DENABLE_PARQUET=ON  \
    -DBUILD_STATIC=OFF \
    -DNNG_ENABLE_TLS=ON \
    -DENABLE_FILETRANSFER=ON \
    -DDEBUG=ON \
    -DNNG_TESTS=OFF .. && make -j8 && make install
