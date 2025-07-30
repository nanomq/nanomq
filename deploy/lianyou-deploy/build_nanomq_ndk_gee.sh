
#!/bin/bash

INSTALL_DIR=${1:-"/tmp"}
NDK_VERSION="android-ndk-r23c"
NDK_DIR="${INSTALL_DIR}/${NDK_VERSION}"
NDK_URL="https://assets.emqx.com/data/ndk/android-ndk-r23c-20250515.tar.gz"

export ANDROID_NDK=$NDK_DIR
export ANDROID_NDK_HOME=$NDK_DIR
export PATH=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH


wget ${NDK_URL} -O ${NDK_DIR}.tar.gz
tar -zxvf ${NDK_DIR}.tar.gz -C /tmp


git clone git@github.com:Mbed-TLS/mbedtls.git
cd mbedtls && mkdir build_android && cd build_android
git checkout v3.6.2 && git submodule update --init --recursive 

cmake -DANDROID_PLATFORM=android-30 \
    -DANDROID_ABI=arm64-v8a \
    -DCMAKE_SYSTEM_NAME=Android\
    -DCMAKE_INSTALL_PREFIX=$NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/sysroot/ \
    -DCMAKE_C_COMPILER_TARGET="aarch64-none-linux-android30" \
    -DCMAKE_TOOLCHAIN_FILE=$NDK_DIR/build/cmake/android.toolchain.cmake \
    -DENABLE_TESTING=OFF \
    -DUSE_SHARED_MBEDTLS_LIBRARY=On \
    ..
make && make install

echo "Start clean build_android_90"
rm -rf build_android_90 build_android_8155
mkdir build_android_90 build_android_8155
cd build_android_90

echo "Start build for Android(90)"

cmake -DANDROID_PLATFORM=android-30 \
    -DANDROID_ABI=arm64-v8a \
    -DCMAKE_TOOLCHAIN_FILE=$NDK_DIR/build/cmake/android.toolchain.cmake \
    -DENABLE_PARQUET=ON \
    -DENABLE_FILETRANSFER=ON \
    -DENABLE_PARQUET_SHARED=ON \
    -DNNG_ENABLE_TLS=ON \
    -DNNG_TLS_ENGINE=open \
    -DTLS_EXTERN_PRIVATE_KEY=ON \
    -DTLS_EXTERN_PRIVATE_KEY_8155=OFF \
    ..

echo "Start make"
make -j8

mkdir lib
cp $NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/sysroot/lib/*.so lib
cd -
echo "Build done" 
#################################################################

echo "Start build for Android(8155)"

cd build_android_8155

cmake -DANDROID_PLATFORM=android-30 \
    -DANDROID_ABI=arm64-v8a \
    -DCMAKE_TOOLCHAIN_FILE=$NDK_DIR/build/cmake/android.toolchain.cmake \
    -DENABLE_PARQUET=ON \
    -DENABLE_FILETRANSFER=ON \
    -DENABLE_PARQUET_SHARED=ON \
    -DNNG_ENABLE_TLS=ON \
    -DNNG_TLS_ENGINE=open \
    -DTLS_EXTERN_PRIVATE_KEY=ON \
    -DTLS_EXTERN_PRIVATE_KEY_8155=ON \
    ..

echo "Start make"
make -j8

mkdir lib
cp $NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/sysroot/lib/*.so lib

echo "Build done" 





echo "Clear Ndk"
rm -rf $NDK_DIR ${NDK_DIR}.tar.gz
