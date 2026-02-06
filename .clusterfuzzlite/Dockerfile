FROM gcr.io/oss-fuzz-base/base-builder

# Install dependencies for Arrow/Parquet
RUN apt-get update && apt-get install -y wget lsb-release pkg-config libssl-dev ca-certificates gnupg \
    && wget https://apache.jfrog.io/artifactory/arrow/$(lsb_release --id --short | tr 'A-Z' 'a-z')/apache-arrow-apt-source-latest-$(lsb_release --codename --short).deb \
    && apt-get install -y -V ./apache-arrow-apt-source-latest-$(lsb_release --codename --short).deb \
    && apt-get update \
    && apt-get install -y -V libarrow-dev libparquet-dev

# NanoMQ source
COPY . $SRC/nanomq
WORKDIR $SRC/nanomq

RUN cp .clusterfuzzlite/build.sh /src/build.sh
RUN chmod +x /src/build.sh
