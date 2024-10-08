#! /bin/bash

set -ex

JOBS=$1
DEBUG=$2
ZIP_NAME=$3
TRUST_VERIFICATION=$4
CA_NAME=$5

# Compile the wazuh agent for Windows
FLAGS="-j ${JOBS} IMAGE_TRUST_CHECKS=${TRUST_VERIFICATION} CA_NAME=\"${CA_NAME}\" "

if [[ "${DEBUG}" = "yes" ]]; then
    FLAGS+="DEBUG=1 "
fi

if [ -z "${BRANCH}"]; then
    mkdir /openarmor-local-src
    cp -r /local-src/* /openarmor-local-src
else
    URL_REPO=https://github.com/wazuh/wazuh/archive/${BRANCH}.zip

    # Download the wazuh repository
    wget -O wazuh.zip ${URL_REPO} && unzip wazuh.zip
fi

bash -c "make -C /openarmor-*/src deps TARGET=winagent ${FLAGS}"
bash -c "make -C /openarmor-*/src TARGET=winagent ${FLAGS}"

rm -rf /openarmor-*/src/external

zip -r /shared/${ZIP_NAME} /openarmor-*
