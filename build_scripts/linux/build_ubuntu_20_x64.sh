#!/bin/bash
set -e

USER_NAME=$(whoami)
CURRENT_DIR=$(pwd)

echo "USER_NAME: ${USER_NAME}"
echo "CURRENT_DIR: ${CURRENT_DIR}"
echo "Create needed directories"

mkdir -p "${CURRENT_DIR}"/build
BUILD_DIR="${CURRENT_DIR}"/build
OPENSSL_LIB_DIR="/usr/lib/x86_64-linux-gnu"
POSTGRE_LIB_DIR="/usr/lib/x86_64-linux-gnu"

HOME_DIR="/home/${USER_NAME}"
INSTALL_DIR="${HOME_DIR}"/uauth
rm -rf ${INSTALL_DIR}
mkdir -p "${HOME_DIR}"/uauth

#cmake options
CMAKE_PATH="/usr/bin/cmake"
CMAKE_MAKE_PROGRAM="/usr/bin/ninja"

#run cmake
cd "${BUILD_DIR}"
${CMAKE_PATH}  ../../.. `
` -DCMAKE_MAKE_PROGRAM=$CMAKE_MAKE_PROGRAM`
` -DCMAKE_INSTALL_PREFIX=$INSTALL_DIR`
` -GNinja`
` -DCMAKE_BUILD_TYPE:String=Release`
` -DCMAKE_C_COMPILER:STRING=/usr/bin/gcc`
` -DCMAKE_CXX_COMPILER:STRING=/usr/bin/g++

#build and install targets
${CMAKE_PATH}  --build . --parallel --target all install
rm -rf "${BUILD_DIR}"

mkdir -p ${INSTALL_DIR}/lib
LIB_DIR=${INSTALL_DIR}/lib

cp -f ${POSTGRE_LIB_DIR}/libpq.so.5.12 ${LIB_DIR}/libpq.so.5.12
cp -f ${OPENSSL_LIB_DIR}/libssl.so.1.1    ${LIB_DIR}/libssl.so.1.1
cp -f ${OPENSSL_LIB_DIR}/libcrypto.so.1.1 ${LIB_DIR}/libcrypto.so.1.1
