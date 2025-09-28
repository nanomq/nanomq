# AMD64 (x86_64) Basic Dockerfile contains following features or modules:
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
    apt-get install -y build-essential cmake pkg-config

WORKDIR /opt
COPY ./OpenSSL_1_1_1k.tar.gz ./mbedtls-3.6.4.tar.bz2 ./zeromq-4.3.4.tar.gz .
RUN tar xzf OpenSSL_1_1_1k.tar.gz
RUN tar xjf mbedtls-3.6.4.tar.bz2
RUN tar xzf zeromq-4.3.4.tar.gz

WORKDIR /opt/openssl-OpenSSL_1_1_1k
RUN ./Configure linux-x86_64 --prefix=/usr/local/ -fPIC && \
    make -j8 && make install_sw

WORKDIR /opt/mbedtls-3.6.4
RUN mkdir build && cd build && \
    cmake -DENABLE_TESTING=OFF -DCMAKE_INSTALL_PREFIX=/usr/local/ .. && \
    make -j8 && make install

WORKDIR /opt/zeromq-4.3.4
RUN mkdir build && cd build && \
    cmake -DBUILD_SHARED=OFF -DCMAKE_INSTALL_PREFIX=/usr/local/ -DZMQ_BUILD_TESTS=OFF \
      -DENABLE_CPACK=OFF -DWITH_DOC=OFF -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_CROSSCOMPILING=OFF -DWITH_LIBBSD=OFF .. && \
    make -j8 && make install

WORKDIR /opt
RUN rm -rf /opt/*
