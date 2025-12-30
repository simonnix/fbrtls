#!/bin/bash

PKI_DIR="${PKI_DIR:-$(dirname $0)/../test_pki}"
ROOT_CA_CERT="${PKI_DIR}/cacert.pem"

INTER_CA_CERT="${PKI_DIR}/certs/intermediate/cacert.pem"
INTER_CRL="${PKI_DIR}/certs/intermediate/crl.pem"

SERVER_CERT="${PKI_DIR}/certs/intermediate/certs/server/fullchain.pem"
CLIENT_CERT="${PKI_DIR}/certs/intermediate/certs/client/fullchain.pem"
REVOKED_CERT="${PKI_DIR}/certs/intermediate/certs/revoked/fullchain.pem"

function indent() {
  local n="$1"
  local f="$2"

  cat "$f" | while read line ; do
    echo "$( eval "printf ' %.0s' {1..$n}" )${line}"
  done
}

function nindent() {
  local n="$1"
  local f="$2"
  local data="$(indent "$n" "$f")"
  echo "${data/#$(eval "printf ' %.0s' {1..$n}")}"
}

cat <<- EOL
	services:
	  hello:
	    port: 3000
	  crl:
	    port: 3001
	  ocsp:
	    port: 3002
	tls:
	  path:
	    root: ${ROOT_CA_CERT}
	    intermediate: ${INTER_CA_CERT}
	    crl: ${INTER_CRL}
	    server: ${SERVER_CERT}
	    client: ${CLIENT_CERT}
	    revoked: ${REVOKED_CERT}
	  value:
	    root: |-
	      $( nindent 6 "${ROOT_CA_CERT}")
	    intermediate: |-
	      $( nindent 6 "${INTER_CA_CERT}")
	    crl: |- 
	      $( nindent 6 "${INTER_CRL}")
	    server: |-
	      $( nindent 6 "${SERVER_CERT}")
	    client: |-
	      $( nindent 6 "${CLIENT_CERT}")
	    revoked: |-
	      $( nindent 6 "${REVOKED_CERT}")
EOL
