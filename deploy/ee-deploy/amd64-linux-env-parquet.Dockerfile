# AMD64 (x86_64) Parquet Dockerfile contains following features or modules:
# * All features in Basic.
# * Parquet
# *   REQUIRES boost
# *   REQUIRES thrift
# *   REQUIRES zstd

FROM wangha666/edge-amd64-linux-env-basic:1.1.0

RUN apt-get update && \
    apt-get install -y p7zip-full flex bison && \
	apt-get autoremove -y && \
	rm -rf /var/lib/apt/lists/*

WORKDIR /opt
COPY ./boost_1_78_0.7z ./thrift.tar.gz ./arrow.tar.gz .

WORKDIR /opt
RUN 7za x boost_1_78_0.7z && cd boost_1_78_0 && \
    ./bootstrap.sh && ./b2 target-os=linux --prefix=/usr/local/ -j8 install && \
	cd /opt && rm -rf boost_1_78_0

WORKDIR /opt
RUN tar -xzf ./thrift.tar.gz && cd thrift && \
    mkdir -p build && cd build && \
    cmake -DBUILD_CPP=ON \
          -DBUILD_COMPILER=ON \
          -DBUILD_TESTING=OFF \
          -DBUILD_C_GLIB=OFF \
          -DBUILD_AS3=OFF \
          -DBUILD_JAVA=OFF \
          -DBUILD_JAVASCRIPT=OFF \
          -DBUILD_NODEJS=OFF \
          -DBUILD_PYTHON=OFF \
          -DBUILD_HASKELL=OFF \
          -DWITH_QT5=OFF \
          -DWITH_OPENSSL=ON \
          -DCMAKE_PREFIX_PATH="/usr/local" \
          .. && make -j8 && make install && \
	cd /opt && rm -rf thrift

WORKDIR /opt
RUN tar -xzf ./arrow.tar.gz && cd arrow/cpp && \
    mkdir -p build && cd build && \
    cmake -DARROW_PARQUET=ON \
          -DARROW_BUILD_SHARED=OFF \
          -DARROW_WITH_BROTLI=ON \
          -DARROW_WITH_BZ2=ON \
          -DARROW_WITH_LZ4=ON \
          -DARROW_WITH_SNAPPY=ON \
          -DARROW_WITH_ZLIB=ON \
          -DARROW_JEMALLOC=OFF\
          -DARROW_WITH_ZSTD=ON \
          -DARROW_USE_OPENSSL=ON \
          -DPARQUET_REQUIRE_ENCRYPTION=ON \
          .. && make -j8 && make install && \
	cd /opt && rm -rf arrow
