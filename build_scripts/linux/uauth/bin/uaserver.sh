#!/bin/bash
set -e

#uauth server params
export UA_HOST="127.0.0.1"
export UA_PORT="8030"

#ucontrol client params
export UA_UC_HOST="127.0.0.1"
export UA_UC_PORT="5678"

#//database params
export UA_DB_NAME="u-auth"
export UA_DB_HOST="dev3.u-system.tech"
export UA_DB_PORT="5436"
export UA_DB_USER="u-backend"
export UA_DB_PASS="u-backend"

export UA_DB_POOL_SIZE_MIN="1"
export UA_DB_POOL_SIZE_MAX="100"
export UA_LOG_LEVEL="0"

export UA_ORIGINS="[http://127.0.0.1:8030]"
export UA_SSL_WEB_CRT_VALID="365"

#uauth certificates part
export UA_CA_CRT_PATH="/home/yaroslav/x509/root-ca.pem"
export UA_SIGNING_CA_CRT_PATH="/home/yaroslav/x509/signing-ca.pem"
export UA_SIGNING_CA_KEY_PATH="/home/yaroslav/x509/signing-ca-key.pem"
export UA_SIGNING_CA_KEY_PASS="U$vN#@D,v)*$N9\N"

#ucontrol certificates part
export UA_CLIENT_CRT_PATH="/home/yaroslav/x509/clientCert.pem"
export UA_CLIENT_KEY_PATH="/home/yaroslav/x509/clientPrivateKey.pem"
export UA_CLIENT_KEY_PASS="password"

#sentry params
export UA_SENTRY_DSN=""
export UA_SENTRY_TRACES_SAMPLE_RATE=""

./uaserver

