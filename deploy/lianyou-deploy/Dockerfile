FROM xuesengxinyi/parquet-cross-compile:ubuntu18.04

# 安装基本工具和依赖
RUN apt-get update && \
    apt-get install -y build-essential

# 安装 ARM64 交叉编译工具链
RUN apt-get install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu

# COPY NanoMQ_mirror 源代码
WORKDIR /opt
COPY ../.. ./NanoMQ_mirror/

# 编译 nanomq
WORKDIR /opt/NanoMQ_mirror
RUN mkdir build && cd build && cmake -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc \
      -DCMAKE_CXX_COMPILER=aarch64-linux-gnu-g++ \
      -DENABLE_PARQUET=ON  \
      -DENABLE_FILETRANSFER=ON \
      -DCMAKE_FIND_ROOT_PATH=/usr/lib/aarch64-linux-gnu/\
      -DNNG_TESTS=OFF .. && make -j32 && make install


RUN mkdir build-debug && cd build-debug && cmake -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc \
      -DCMAKE_CXX_COMPILER=aarch64-linux-gnu-g++ \
      -DENABLE_PARQUET=ON  \
      -DENABLE_FILETRANSFER=ON \
      -DDEBUG=ON\
      -DASAN=ON\
      -DCMAKE_FIND_ROOT_PATH=/usr/lib/aarch64-linux-gnu/\
      -DNNG_TESTS=OFF .. && make -j32 && make install
