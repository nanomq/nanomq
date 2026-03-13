FROM gcr.io/oss-fuzz-base/base-builder

# Install dependencies for Arrow/Parquet
RUN apt-get update && apt-get install -y wget lsb-release pkg-config libssl-dev ca-certificates gnupg \
    && wget https://apache.jfrog.io/artifactory/arrow/$(lsb_release --id --short | tr 'A-Z' 'a-z')/apache-arrow-apt-source-latest-$(lsb_release --codename --short).deb \
    && apt-get install -y -V ./apache-arrow-apt-source-latest-$(lsb_release --codename --short).deb \
    && apt-get update \
    && apt-get install -y -V libarrow-dev libparquet-dev libmbedtls-dev patchelf

# Install mimalloc from source (since it's not in Ubuntu 20.04 repos)
RUN git clone --depth 1 https://github.com/microsoft/mimalloc.git && \
    cd mimalloc && \
    mkdir build && cd build && \
    cmake .. -DMI_BUILD_SHARED=OFF -DMI_BUILD_STATIC=ON -DMI_INSTALL_TOPLEVEL=ON -DMI_OVERRIDE=OFF -DMI_BUILD_TESTS=OFF && \
    make -j$(nproc) && \
    make install && \
    cd ../.. && \
    rm -rf mimalloc

# NanoMQ source
COPY . $SRC/nanomq
WORKDIR $SRC/nanomq

RUN cp .clusterfuzzlite/build.sh /src/build.sh
RUN chmod +x /src/build.sh
