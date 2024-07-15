FROM xuesengxinyi/parquet-compile:ubuntu18.04

# 重新编译 parquet
WORKDIR /opt/arrow/cpp
RUN mkdir build-new && cd build-new &&\
    cmake -DARROW_PARQUET=ON  \
        -DARROW_WITH_BROTLI=ON \
        -DARROW_WITH_BZ2=ON \
        -DARROW_WITH_LZ4=ON \
        -DARROW_WITH_SNAPPY=ON \
        -DARROW_WITH_ZLIB=OFF \
        -DARROW_BUILD_UTILITIES=ON \
        -DARROW_JEMALLOC=OFF\
        -DARROW_WITH_ZSTD=ON \
        -DARROW_USE_OPENSSL=ON \
        -DARROW_BUILD_STATIC=ON  \
        -DARROW_BUILD_SHARED=OFF \
        -DPARQUET_REQUIRE_ENCRYPTION=ON \
        -DARROW_THRIFT_USE_SHARED=OFF \
        -DARROW_OPENSSL_USE_SHARED=OFF \
        -DARROW_BZ2_USE_SHARED=OFF \
        -DARROW_LZ4_USE_SHARED=OFF \
        -DARROW_ZSTD_USE_SHARED=OFF \
        .. && make -j2 && make install

# COPY NanoMQ_mirror 源代码
WORKDIR /opt
COPY ../.. ./NanoMQ_mirror/

# 编译 nanomq
WORKDIR /opt/NanoMQ_mirror
RUN mkdir build && cd build && cmake \
     -DENABLE_PARQUET=ON  \
     -DNNG_ENABLE_TLS=ON \
     -DENABLE_FILETRANSFER=ON \
     -DNNG_TESTS=OFF .. && make -j32 && make install

RUN mkdir build-debug && cd build-debug && cmake \
    -DENABLE_PARQUET=ON  \
    -DNNG_ENABLE_TLS=ON \
    -DENABLE_FILETRANSFER=ON \
    -DDEBUG=ON \
    -DNNG_TESTS=OFF .. && make -j32 && make install
