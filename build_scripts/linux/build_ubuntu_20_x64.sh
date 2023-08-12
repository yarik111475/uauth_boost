#!/bin/bash
set -e

CURRENT_DIR=$(pwd)

echo "CURRENT_DIR: ${CURRENT_DIR}"
echo "Create needed directories"

BUILD_DIR=${CURRENT_DIR}/build
rm -rf ${BUILD_DIR} && mkdir -p ${BUILD_DIR}

INSTALL_DIR=${U_AUTH_DIR}
rm -rf ${INSTALL_DIR} && mkdir -p ${INSTALL_DIR}

#cmake options
CMAKE_PATH="/usr/bin/cmake"
CMAKE_MAKE_PROGRAM="/usr/bin/ninja"

#run cmake
cd ${BUILD_DIR}
VERSION=${VERSION} ${CMAKE_PATH}  ../../.. `
` -DCMAKE_MAKE_PROGRAM=$CMAKE_MAKE_PROGRAM`
` -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR`
` -GNinja`
` -DCMAKE_BUILD_TYPE:String=Release`
` -DCMAKE_C_COMPILER:STRING=/usr/bin/gcc`
` -DCMAKE_CXX_COMPILER:STRING=/usr/bin/g++

#build and install targets
${CMAKE_PATH}  --build . --parallel --target all install
rm -rf ${BUILD_DIR}


LIB_DIR=${INSTALL_DIR}/lib
mkdir -p ${LIB_DIR}

OPENSSL_LIB_DIR="/usr/lib/x86_64-linux-gnu"
POSTGRE_LIB_DIR="/usr/lib/x86_64-linux-gnu"

cp -Lf ${POSTGRE_LIB_DIR}/libpq.so.5 ${LIB_DIR}/libpq.so.5
cp -f ${OPENSSL_LIB_DIR}/libssl.so.1.1    ${LIB_DIR}/libssl.so.1.1
cp -f ${OPENSSL_LIB_DIR}/libcrypto.so.1.1 ${LIB_DIR}/libcrypto.so.1.1
