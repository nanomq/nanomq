FROM gcr.io/oss-fuzz-base/base-builder

# NanoMQ 源码
COPY . $SRC/nanomq
WORKDIR $SRC/nanomq

RUN cp .clusterfuzzlite/build.sh /src/build.sh
RUN chmod +x /src/build.sh

# 执行 clusterfuzzlite 的 build.sh
# RUN bash .clusterfuzzlite/build.sh
