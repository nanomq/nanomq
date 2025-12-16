FROM gcr.io/oss-fuzz-base/base-builder

ENV FUZZING_LANGUAGE=c++
RUN apt-get update && apt-get install -y \
    cmake \
    ninja-build \
    libssl-dev \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Copy whole repo
COPY . .

# Build fuzzers
RUN compile
