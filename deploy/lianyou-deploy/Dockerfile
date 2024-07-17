FROM xuesengxinyi/parquet-compile:ubuntu18.04

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
