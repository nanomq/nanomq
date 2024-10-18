#!/bin/bash
set -euo pipefail

INSTALL_DIR=${1:-"/tmp"}
NDK_VERSION="android-ndk-r23c"
NDK_URL="https://dl.google.com/android/repository/${NDK_VERSION}-linux.zip"
NDK_DIR="${INSTALL_DIR}/${NDK_VERSION}"

# Step 1: Prepare NDK
echo "Downloading Android NDK..."
wget ${NDK_URL} -O ${NDK_DIR}.zip

echo "Unzipping NDK..."
unzip ${NDK_DIR}.zip -d ${INSTALL_DIR}

# Step 2: Compile OpenSSL
OPENSSL_REPO="https://github.com/openssl/openssl.git"
OPENSSL_DIR=${INSTALL_DIR}/"openssl"

echo "Cloning OpenSSL repository..."
git clone ${OPENSSL_REPO} $OPENSSL_DIR

echo "Creating build script for OpenSSL..."
cat <<EOF > ${OPENSSL_DIR}/build_android.sh
#!/bin/bash
export ANDROID_NDK_ROOT=${NDK_DIR}
export PATH=\$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin:\$PATH
./Configure android-arm64 -D__ANDROID_API__=30 --prefix=\$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/sysroot
make -j1
make install
EOF

echo "Making build script executable..."
chmod +x ${OPENSSL_DIR}/build_android.sh

echo "Building OpenSSL for Android..."
cd ${OPENSSL_DIR} && ./build_android.sh

echo "OpenSSL build and installation completed."

# Step 3: Modify NDK toolchain configuration
echo "Modifying NDK toolchain configuration for Android build..."
sed -i 's/set(ANDROID_ABI armeabi-v7a)/set(ANDROID_ABI arm64-v8a)/' ${NDK_DIR}/build/cmake/android-legacy.toolchain.cmake

# Step 4: Clone Arrow repository
ARROW_REPO="https://github.com/apache/arrow.git"
ARROW_DIR=${INSTALL_DIR}/"arrow"

echo "Cloning Arrow repository..."
git clone ${ARROW_REPO} ${ARROW_DIR}

# Step 5: Apply patch to Arrow CMakeLists.txt
echo "Patching Arrow CMakeLists.txt for Android support..."
cd ${ARROW_DIR}/cpp && sed -i 's/if(NOT WIN32 AND NOT APPLE)/if(NOT WIN32 AND NOT APPLE AND NOT ANDROID)/' src/arrow/CMakeLists.txt

# Step 6: Compile Arrow parquet
echo "Start clean build_android"
rm -rf build_android
mkdir build_android
cd build_android

echo "Start build for Android"

cmake -DANDROID_ABI="arm64-v8a" \
    -DANDROID_PLATFORM="android-30" \
    -DCMAKE_SYSTEM_NAME=Android \
    -DCMAKE_TOOLCHAIN_FILE=$NDK_DIR/build/cmake/android-legacy.toolchain.cmake \
    -DARROW_THRIFT_USE_SHARED=OFF \
    -DCMAKE_INSTALL_PREFIX=$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/sysroot/ \
    -DCMAKE_C_COMPILER_TARGET="aarch64-none-linux-android30" \
    -DPARQUET_LINK_SHARED=OFF \
    -DARROW_WITH_BROTLI=ON \
    -DARROW_WITH_BZ2=OFF \
    -DARROW_WITH_LZ4=ON \
    -DARROW_WITH_SNAPPY=OFF \
    -DARROW_WITH_ZLIB=ON \
    -DARROW_JEMALLOC=OFF\
    -DARROW_WITH_ZSTD=ON \
    -DARROW_USE_OPENSSL=ON \
    -DPARQUET_REQUIRE_ENCRYPTION=ON\
    -DARROW_PARQUET=ON \
    ..

echo "Start make"
make -j1
make install
echo "Build done"