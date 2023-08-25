ARG VERSION

ARG U_AUTH_TEMP_DIR=/opt/usystem/u_auth
ARG DEP_LIBS_PATH=/tmp/u_auth_deps

FROM ubuntu:20.04 as builder

ARG VERSION
ARG U_AUTH_TEMP_DIR
ARG DEP_LIBS_PATH

ARG BOOST_VERSION="1.82.0"


ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /tmp
RUN apt-get update && apt-get install -y ninja-build wget cmake build-essential libpq-dev libssl-dev
RUN export BOOST_VERSION_DASHES=$(echo $BOOST_VERSION | sed 's/\./_/g') ; \
    wget https://boostorg.jfrog.io/artifactory/main/release/${BOOST_VERSION}/source/boost_$BOOST_VERSION_DASHES.tar.gz && \
    tar xvf boost_${BOOST_VERSION_DASHES}.tar.gz && \
    cd boost_${BOOST_VERSION_DASHES} && ./bootstrap.sh --prefix=/usr/local all && ./b2 install

ARG build_script_path=build_scripts/linux
ARG build_script=build_ubuntu_20_x64.sh

COPY ./. /tmp/build

WORKDIR /tmp/build/$build_script_path
RUN chmod +x $build_script
RUN VERSION=$VERSION U_AUTH_DIR=$U_AUTH_TEMP_DIR ./$build_script


FROM ubuntu:20.04 as dependencies


ARG DEP_LIBS_PATH

# gather libpq deps
RUN apt-get update && apt-get install -y --download-only libgssapi-krb5-2 libldap-2.4-2
# OpenSSL required to extract CN from admin certs and ccreate admin account in UAuth
RUN apt-get install -y --download-only openssl
RUN mkdir -p $DEP_LIBS_PATH && cp -r /var/cache/apt/archives/. $DEP_LIBS_PATH


FROM ubuntu:20.04 as base

ARG VERSION
ARG U_AUTH_TEMP_DIR
ARG DEP_LIBS_PATH


ARG U_AUTH_WORK_DIR=/app
RUN mkdir -p $U_AUTH_WORK_DIR
RUN echo $VERSION > $U_AUTH_WORK_DIR/version

# Copy uath
COPY --from=builder $U_AUTH_TEMP_DIR/. $U_AUTH_WORK_DIR/

# copy and install deps as packages
RUN mkdir -p $DEP_LIBS_PATH
COPY --from=dependencies $DEP_LIBS_PATH/. $DEP_LIBS_PATH/
RUN dpkg -R --install $DEP_LIBS_PATH/

COPY start.sh $U_AUTH_WORK_DIR/bin/start.sh
WORKDIR $U_AUTH_WORK_DIR/bin
ENTRYPOINT ["./start.sh"]