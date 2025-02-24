
#!/bin/bash

INSTALL_DIR=${1:-"/tmp"}
NDK_VERSION="android-ndk-r23c"
NDK_DIR="${INSTALL_DIR}/${NDK_VERSION}"
NDK_URL="https://assets.emqx.com/data/ndk/android-ndk-r23c-sdv.tar.gz"

export ANDROID_NDK=$NDK_DIR
export ANDROID_NDK_HOME=$NDK_DIR
export PATH=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH


wget ${NDK_URL} -O ${NDK_DIR}.tar.gz
tar -zxvf ${NDK_DIR}.tar.gz -C /tmp


echo "Start clean build_android"
rm -rf build_android
mkdir build_android
cd build_android

echo "Start build for Android"

cmake -DANDROID_PLATFORM=android-30 \
    -DANDROID_ABI=arm64-v8a \
    -DCMAKE_TOOLCHAIN_FILE=$NDK_DIR/build/cmake/android.toolchain.cmake \
    -DENABLE_PARQUET=ON \
    -DANDROID_STL=c++_shared \
    -DNNG_ENABLE_QUIC=OFF \
    -DENABLE_FILETRANSFER=ON \
    -DENABLE_PARQUET_SHARED=ON \
    -DNNG_ENABLE_TLS=ON \
    -DNNG_TLS_ENGINE=open \
    -DTLS_EXTERN_PRIVATE_KEY=ON \
    ..

echo "Start make"
make -j1


echo "Build done" 

mkdir lib
cp $NDK_DIR/toolchains/llvm/prebuilt/linux-x86_64/sysroot/lib/*.so lib
cp ./nng/src/supplemental/quic/msquic/msquic/bin/Release/libmsquic.so lib

echo "Clear Ndk"
rm -rf $NDK_DIR ${NDK_DIR}.tar.gz
