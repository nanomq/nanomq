# AArch64 (arm64) Basic Dockerfile contains same features or modules as AMD64 has:
# * License REQUIRES OpenSSL.
# * TLS Transport layer REQUIRES mbedtls.
# * ZeroMQ Gateway REQUIRES zeromq.
# *   zeromq REQUIRES pkg-config.
# * QUIC Transport layer.
# * SQLite.
# * JWT.
# * Rule engine.
# * Dashboard.

FROM ubuntu:18.04

RUN apt-get update && \
    apt-get install -y g++-aarch64-linux-gnu gcc-aarch64-linux-gnu pkg-config
    #build-essential

WORKDIR /usr
COPY ./cmake-3.29.0-linux-x86_64.tar.gz .
RUN tar xzf cmake-3.29.0-linux-x86_64.tar.gz
RUN rm /usr/cmake-3.29.0-linux-x86_64.tar.gz

WORKDIR /usr/cmake-3.29.0-linux-x86_64
ENV PATH=$PATH:/usr/cmake-3.29.0-linux-x86_64/bin/

WORKDIR /opt
COPY ./OpenSSL_1_1_1k.tar.gz ./mbedtls-3.6.4.tar.bz2 ./zeromq-4.3.4.tar.gz .
RUN tar xzf OpenSSL_1_1_1k.tar.gz
RUN tar xjf mbedtls-3.6.4.tar.bz2
RUN tar xzf zeromq-4.3.4.tar.gz

WORKDIR /opt/openssl-OpenSSL_1_1_1k
RUN ./Configure linux-aarch64 --prefix=/usr/aarch64-linux-gnu/ --cross-compile-prefix=aarch64-linux-gnu- -fPIC && \
    make -j8 && make install_sw

WORKDIR /opt/mbedtls-3.6.4
RUN mkdir build && cd build && \
    cmake -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc \
          -DCMAKE_CXX_COMPILER=aarch64-linux-gnu-g++ \
          -DCMAKE_INSTALL_PREFIX=/usr/aarch64-linux-gnu/ \
          -DENABLE_TESTING=OFF .. && \
    make -j8 && make install

WORKDIR /opt/zeromq-4.3.4
RUN mkdir build && cd build && \
    cmake -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc \
          -DCMAKE_CXX_COMPILER=aarch64-linux-gnu-g++ \
          -DCMAKE_INSTALL_PREFIX=/usr/aarch64-linux-gnu/ \
          -DCMAKE_STAGING_PREFIX=/usr/aarch64-linux-gnu/ \
          -DCMAKE_PREFIX_PATH=/usr/aarch64-linux-gnu/ \
          -DBUILD_SHARED=OFF -DZMQ_BUILD_TESTS=OFF \
          -DENABLE_CPACK=OFF -DWITH_DOC=OFF -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_CROSSCOMPILING=ON -DWITH_LIBBSD=OFF .. && \
    make -j8 && make install

WORKDIR /opt
RUN rm -rf /opt/*
