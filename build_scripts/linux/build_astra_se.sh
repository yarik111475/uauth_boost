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
INSTALL_DIR="${CURRENT_DIR}"/uauth
rm -rf ${INSTALL_DIR}
mkdir -p "${CURRENT_DIR}"/uauth

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

cp -Lf ${POSTGRE_LIB_DIR}/libpq.so.5      ${LIB_DIR}/libpq.so.5
cp -f ${OPENSSL_LIB_DIR}/libssl.so.1.1    ${LIB_DIR}/libssl.so.1.1
cp -f ${OPENSSL_LIB_DIR}/libcrypto.so.1.1 ${LIB_DIR}/libcrypto.so.1.1

SCRIPT_PATH=${INSTALL_DIR}/bin
UAUTH_SCRIPT_CONTENT="#!/bin/bash
set -e

#uauth server params
export UA_HOST=\"127.0.0.1\"
export UA_PORT=\"8030\"

#ucontrol client params
export UA_UC_HOST=\"127.0.0.1\"
export UA_UC_PORT=\"5678\"

#//database params
export UA_DB_NAME=\"u-auth\"
export UA_DB_HOST=\"dev3.u-system.tech\"
export UA_DB_PORT=\"5436\"
export UA_DB_USER=\"u-backend\"
export UA_DB_PASS=\"u-backend\"

export UA_DB_POOL_SIZE_MIN=\"1\"
export UA_DB_POOL_SIZE_MAX=\"100\"
export UA_LOG_LEVEL=\"0\"

export UA_ORIGINS=\"[http://127.0.0.1:8030]\"
export UA_SSL_WEB_CRT_VALID=\"365\"

#uauth certificates part
export UA_CA_CRT_PATH=\"/home/yaroslav/x509/root-ca.pem\"
export UA_SIGNING_CA_CRT_PATH=\"/home/yaroslav/x509/signing-ca.pem\"
export UA_SIGNING_CA_KEY_PATH=\"/home/yaroslav/x509/signing-ca-key.pem\"
export UA_SIGNING_CA_KEY_PASS=\"U\$vN#@D,v)*\$N9\N\"

#ucontrol certificates part
export UA_CLIENT_CRT_PATH=\"/home/yaroslav/x509/clientCert.pem\"
export UA_CLIENT_KEY_PATH=\"/home/yaroslav/x509/clientPrivateKey.pem\"
export UA_CLIENT_KEY_PASS=\"password\"

#sentry params
export UA_SENTRY_DSN=\"\"
export UA_SENTRY_TRACES_SAMPLE_RATE=\"\"

./uaserver
"

echo "${UAUTH_SCRIPT_CONTENT}" >> "${SCRIPT_PATH}"/uaserver.sh
chmod +x ${SCRIPT_PATH}/uaserver.sh
