FROM xuesengxinyi/parquet-compile:ubuntu18.04

# COPY NanoMQ_mirror 源代码
WORKDIR /opt
COPY ../.. ./NanoMQ_mirror/

# 编译 nanomq
WORKDIR /opt/NanoMQ_mirror
RUN mkdir build && cd build && cmake \
      -DENABLE_PARQUET=ON  \
      -DENABLE_FILETRANSFER=ON \
      -DNNG_TESTS=OFF .. && make -j32 && make install


RUN mkdir build-debug && cd build-debug && cmake \
      -DENABLE_PARQUET=ON  \
      -DENABLE_FILETRANSFER=ON \
      -DDEBUG=ON\
      -DASAN=ON\
      -DNNG_TESTS=OFF .. && make -j32 && make install
