#!/bin/bash
#Copyright © 2025 Simon HUET
#
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in
#all copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#THE SOFTWARE.

set -e

# This is EZ-Test-PKI Bash script
#

# Getting in this script directory.
cd "$(dirname "$0")"

# Importing "vars" file, if it exists
EZTESTPKI_VARS="${EZTESTPKI_VARS:-vars}"
if [ -e "${EZTESTPKI_VARS}" ] ; then
  . "${EZTESTPKI_VARS}"
fi

# OpenSSL configuration file // Defaults to "openssl.cnf"
OPENSSL_CNF=${OPENSSL_CNF:-openssl.cnf}

# PKI_DIR is the main directory where the magic happens, relative to this script.
export PKI_DIR="${PKI_DIR:-test_pki}"

export REQ_COUNTRY="${REQ_COUNTRY:-US}"
export REQ_STATE="${REQ_STATE:-California}"
export REQ_ORGANIZATION="${REQ_ORGANIZATION:-University of California}"
export REQ_EMAIL="${REQ_EMAIL:-rector@univ.ca.edu}"

# Subject Alt Names (for Server)
export REQ_SERVER_SANS="${REQ_SERVER_SANS:-DNS:localhost, IP:127.0.0.1, DNS:univ.ca.edu}"

# CRL Distribution Endpoints
export REQ_CRL_ENDPOINTS="${REQ_CRL_ENDPOINTS:-URI:https://univ.ca.edu/univ.ca.crl}"

# OCSP (authorityInfoAccess)
export REQ_AUTHORITY_INFO_ACCESS="${REQ_AUTHORITY_INFO_ACCESS:-OCSP;URI:http://ocsp.univ.ca.edu}"

# Certificates Directory Name
CA_CERTS_DIR="${CA_CERTS_DIR:-${PKI_DIR}/certs}"

# Certificates commonName
ROOT_COMMON_NAME="${ROOT_COMMON_NAME:-${REQ_ORGANIZATION} Root CA}"

# Certificate days
ROOT_DAYS=${ROOT_DAYS:-10950} # 30 years
INTERMEDIATES_DAYS=${INTERMEDIATES_DAYS:-7300} # 20 years
CERTS_DAYS=${CERTS_DAYS:-3650} # 10 years
CRLS_DAYS=${CRLS_DAYS:-3650} # 10 years

# FILENAMES
CA_CERT_FILENAME="${CA_CERT_FILENAME:-cacert.pem}"
CA_CHAIN_FILENAME="${CA_CHAIN_FILENAME:-ca-chain.pem}"
CRT_FILENAME="${CRT_FILENAME:-cert.pem}"
KEY_FILENAME="${KEY_FILENAME:-key.pem}"
CSR_FILENAME="${CSR_FILENAME:-csr.pem}"
CRL_FILENAME="${CRL_FILENAME:-crl.pem}"

# Certs DIR_NAME
INTERMEDIATE_DIR_NAME="${INTERMEDIATE_DIR_NAME:-intermediate}"
SERVER_DIR_NAME="${SERVER_DIR_NAME:-server}"
CLIENT_DIR_NAME="${CLIENT_DIR_NAME:-client}"
REVOKED_DIR_NAME="${REVOKED_DIR_NAME:-revoked}"

#### PSEUDO-PRIVATE FUNCTIONS

# _init_ca() initialize a CA directory, inside a directory only if it does not exists
function _init_ca() {
  local ca="${1}"

  if [ -d "${ca}" ] ; then
    return
  fi

  for d in "${ca}"/{certs,newcerts} ; do
    if ! [ -d "$d" ] ; then
      mkdir -p "$d"
    fi
  done
  
  if ! [ -e "${ca}"/index.txt ] ; then
    touch "${ca}"/index.txt
  fi

  if ! [ -e "${ca}"/serial ] ; then
    echo 1000 > "${ca}"/serial
  fi
}

# _make_key() creates a new key, using genrsa, named "key.pem" inside a directory if it does not exists
function _make_key() {
  local key_dir_name="$(basename "${1}")"
  local key="${1}/${KEY_FILENAME}"

  if ! [ -e "$key" ] ; then
    echo "# Generating a new key for ${1}" 1>&2
    openssl genrsa -out "$key" 4096
    chmod 400 "$key"
  fi
}

# _make_cert() creates a new cert if it does not exists or if it has expired
function _make_cert() {
  local extension="${1}"

  export REQ_COMMON_NAME="${common_name}"
  export CA_POLICY=policy_intermediate

  _make_key "$CERT_DIR"

  if ! openssl x509 -checkend 86400 -noout -in "${CERT_DIR}/${CERT_FILENAME}" >& /dev/null ; then
    if [ -e "${CERT_DIR}/${CERT_FILENAME}" ] ; then
      echo "# Renewing the ${cert_name^} certificate" 1>&2
    else
      echo "# Generating the ${cert_name^} certificate" 1>&2
    fi
    openssl req -config ${OPENSSL_CNF} ${REQ_OPTS} -new -sha256 \
      -key "${CERT_DIR}/${KEY_FILENAME}"  \
      -out "${CERT_DIR}/${CSR_FILENAME}" \
      -batch

    # 4. Sign the Intermediate CSR with the Root CA (using ${OPENSSL_CNF})
    openssl ca -config ${OPENSSL_CNF} -extensions ${extension} \
      -days ${CERT_DAYS} -notext -md sha256 \
      -in "${CERT_DIR}/${CSR_FILENAME}" \
      -out "${CERT_DIR}/${CERT_FILENAME}" \
      -batch
  fi
}

# PUBLIC FUNCTIONS

# make_ca_cert() creates a new intermediate certificate signed by our Root CA
function make_ca_cert() {
  local ca_name="${1}"
  local common_name="${2}"
  local cert_name="${ca_name}"

  export CA_DIR="${PKI_DIR}"

  local CERT_DIR="${CA_DIR}/certs/${ca_name}"
  local CERT_DAYS="${INTERMEDIATES_DAYS}"
  local CERT_FILENAME="${CA_CERT_FILENAME}"
  _init_ca "${CA_CERTS_DIR}/${ca_name}"

  _make_cert intermediate_ca_cert

  cat "${CERT_DIR}/${CA_CERT_FILENAME}" "${PKI_DIR}/${CA_CERT_FILENAME}" > "${CERT_DIR}/${CA_CHAIN_FILENAME}"
}

# make_server_cert() creates a new "server" certificate signed by an intermediate CA
function make_server_cert() {
  local ca_name="${1}"
  local cert_name="${2}"
  local common_name="${3}"

  export CA_DIR="${PKI_DIR}/certs/${ca_name}"

  #local CERT_DIR="${CA_CERTS_DIR}/${ca_name}/certs/${cert_name}"
  local CERT_DIR="${CA_DIR}/certs/${cert_name}"
  local CERT_DAYS="${CERTS_DAYS}"
  local CERT_FILENAME="${CRT_FILENAME}"
  [ -d "${CERT_DIR}" ] || mkdir "${CERT_DIR}"

  local REQ_OPTS="-reqexts req_server_ext"
  _make_cert server_cert

  cat "${CERT_DIR}/${CRT_FILENAME}" "${CERT_DIR}/${KEY_FILENAME}" "${CA_DIR}/${CA_CERT_FILENAME}" > "${CERT_DIR}/fullchain.pem"
}

# make_server_cert() creates a new "client" certificate signed by an intermediate CA
function make_client_cert() {
  local ca_name="${1}"
  local cert_name="${2}"
  local common_name="${3}"

  export CA_DIR="${PKI_DIR}/certs/${ca_name}"

  #local CERT_DIR="${CA_CERTS_DIR}/${ca_name}/certs/${cert_name}"
  local CERT_DIR="${CA_DIR}/certs/${cert_name}"
  local CERT_DAYS="${CERTS_DAYS}"
  local CERT_FILENAME="${CRT_FILENAME}"
  [ -d "${CERT_DIR}" ] || mkdir "${CERT_DIR}"

  _make_cert client_cert

  cat "${CERT_DIR}/${CRT_FILENAME}" "${CERT_DIR}/${KEY_FILENAME}" "${CA_DIR}/${CA_CERT_FILENAME}" > "${CERT_DIR}/fullchain.pem"
}

function verify_cert() {
  local ca_name="${1}"
  local cert_name="${2}"

  export CA_DIR="${PKI_DIR}/certs/${ca_name}"
  local CERT_DIR="${CA_CERTS_DIR}/${ca_name}/certs/${cert_name}"
  local CERT_FILENAME="${CRT_FILENAME}"

  if ! openssl x509 -checkend 86400 -noout -in "${CERT_DIR}/${CERT_FILENAME}" >& /dev/null ; then
    return 1
  fi

  if [ -e "${CA_DIR}/${CRL_FILENAME}" ] ; then
    if ! openssl verify -CAfile "${PKI_DIR}/${CA_CERT_FILENAME}" \
      -untrusted "${CA_DIR}/${CA_CERT_FILENAME}" \
      -CRLfile "${CA_DIR}/${CRL_FILENAME}" \
      -crl_check "${CA_DIR}/certs/${cert_name}/${CRT_FILENAME}" >& /dev/null ; then
      return 2
    fi
  elif ! openssl verify -CAfile "${PKI_DIR}/${CA_CERT_FILENAME}" \
    -untrusted "${CA_DIR}/${CA_CERT_FILENAME}" \
    "${CERT_DIR}/${CERT_FILENAME}" >& /dev/null ; then
    return 3
  fi
}

# revoked_cert() revokes any certificate signed by an intermediate CA
function revoke_cert() {
  local ca_name="${1}"
  local cert_name="${2}"

  export CA_DIR="${PKI_DIR}/certs/${ca_name}"

  if [ -e "${CA_DIR}/${CRL_FILENAME}" ] ; then
    openssl verify -CAfile "${PKI_DIR}/${CA_CERT_FILENAME}" \
      -untrusted "${CA_DIR}/${CA_CERT_FILENAME}" \
      -CRLfile "${CA_DIR}/${CRL_FILENAME}" \
      -crl_check "${CA_DIR}/certs/${cert_name}/${CRT_FILENAME}" >& /dev/null || true && return
  fi

  openssl ca -config ${OPENSSL_CNF} -revoke "${CA_DIR}/certs/${cert_name}/${CRT_FILENAME}"
  openssl ca -config ${OPENSSL_CNF} -gencrl -crlexts req_ext -crldays ${CRLS_DAYS} -out "${CA_DIR}/${CRL_FILENAME}"
}

#--- ROOT

# 1. Initialize the Root CA directory
export CA_POLICY=policy_strict
export CA_DIR="${PKI_DIR}"

_init_ca "${CA_DIR}"

# 2. Create the Root CA Private Key
_make_key "$CA_DIR"

# 3. Create the Self-Signed Root CA Certificate (using ${OPENSSL_CNF})
export REQ_COMMON_NAME="${ROOT_COMMON_NAME}"
if ! openssl x509 -checkend 86400 -noout -in "${CA_DIR}/cacert.pem" >& /dev/null ; then
  echo "# Generating the self-signed Root certificate" 1>&2
  openssl req -config ${OPENSSL_CNF} -new -x509 -days ${ROOT_DAYS} -sha256 -extensions root_ca_cert \
    -key "${CA_DIR}/key.pem" \
    -out "${CA_DIR}/cacert.pem" \
    -batch
fi

#--- INTERMEDIATE
make_ca_cert "${INTERMEDIATE_DIR_NAME}" "${REQ_ORGANIZATION} Intermediate CA"

#--- SERVER
make_server_cert "${INTERMEDIATE_DIR_NAME}" "${SERVER_DIR_NAME}" "${REQ_ORGANIZATION} Test Server certificate"

#--- CLIENT
make_client_cert "${INTERMEDIATE_DIR_NAME}" "${CLIENT_DIR_NAME}" "${REQ_ORGANIZATION} Test Client certificate"

#--- REVOKE
make_client_cert "${INTERMEDIATE_DIR_NAME}" "${REVOKED_DIR_NAME}" "${REQ_ORGANIZATION} Revoked Client certificate"
revoke_cert "${INTERMEDIATE_DIR_NAME}" "${REVOKED_DIR_NAME}"

#--- VERIFY
CERTS_DIR="${PKI_DIR}/certs/${INTERMEDIATE_DIR_NAME}/certs"

openssl verify -CAfile "${PKI_DIR}/${CA_CERT_FILENAME}" \
  "${CA_CERTS_DIR}/${INTERMEDIATE_DIR_NAME}/${CA_CERT_FILENAME}"

openssl verify -CAfile "${PKI_DIR}/${CA_CERT_FILENAME}" \
  -untrusted "${CA_CERTS_DIR}/${INTERMEDIATE_DIR_NAME}/${CA_CERT_FILENAME}" \
  "${CERTS_DIR}/${SERVER_DIR_NAME}/${CRT_FILENAME}"

openssl verify -CAfile "${CA_CERTS_DIR}/${INTERMEDIATE_DIR_NAME}/${CA_CHAIN_FILENAME}" \
  "${CERTS_DIR}/${CLIENT_DIR_NAME}/${CRT_FILENAME}"

openssl verify -CAfile "${CA_CERTS_DIR}/${INTERMEDIATE_DIR_NAME}/${CA_CHAIN_FILENAME}" \
  -CRLfile "${PKI_DIR}/certs/${INTERMEDIATE_DIR_NAME}/${CRL_FILENAME}" \
  -crl_check "${CERTS_DIR}/${CLIENT_DIR_NAME}/${CRT_FILENAME}"

openssl verify -CAfile "${CA_CERTS_DIR}/${INTERMEDIATE_DIR_NAME}/${CA_CHAIN_FILENAME}" \
  -CRLfile "${PKI_DIR}/certs/${INTERMEDIATE_DIR_NAME}/${CRL_FILENAME}" \
  -crl_check "${CERTS_DIR}/${REVOKED_DIR_NAME}/${CRT_FILENAME}" >& /dev/null|| true

echo "OK"
