#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

DAYS_VALID=3650
DAYS_EXPIRED=0

echo "=== Generating Root CA ==="
openssl genpkey -algorithm ed25519 -out root-ca.key
openssl req -new -x509 -key root-ca.key -out root-ca.pem \
    -days $DAYS_VALID -subj "/CN=Test Root CA/O=Erlkoenig Test"

echo "=== Generating Sub CA ==="
openssl genpkey -algorithm ed25519 -out sub-ca.key
openssl req -new -key sub-ca.key -out sub-ca.csr \
    -subj "/CN=Test Sub-CA/O=FinSecure Test"
openssl x509 -req -in sub-ca.csr -CA root-ca.pem -CAkey root-ca.key \
    -CAcreateserial -out sub-ca.pem -days $DAYS_VALID \
    -extfile <(printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign")

echo "=== Generating Signing Cert ==="
openssl genpkey -algorithm ed25519 -out signing.key
openssl req -new -key signing.key -out signing.csr \
    -subj "/CN=test-pipeline/O=FinSecure Test"
openssl x509 -req -in signing.csr -CA sub-ca.pem -CAkey sub-ca.key \
    -CAcreateserial -out signing.pem -days $DAYS_VALID \
    -extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature")

echo "=== Generating Expired Cert ==="
openssl genpkey -algorithm ed25519 -out expired.key
openssl req -new -key expired.key -out expired.csr \
    -subj "/CN=expired-cert/O=Test"
openssl x509 -req -in expired.csr -CA sub-ca.pem -CAkey sub-ca.key \
    -CAcreateserial -out expired.pem -days $DAYS_EXPIRED \
    -extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature")

echo "=== Generating Wrong CA (independent root) ==="
openssl genpkey -algorithm ed25519 -out wrong-ca.key
openssl req -new -x509 -key wrong-ca.key -out wrong-ca.pem \
    -days $DAYS_VALID -subj "/CN=Wrong Root CA/O=Evil Corp"

echo "=== Generating Wrong Signing Cert (signed by wrong CA) ==="
openssl genpkey -algorithm ed25519 -out wrong-signing.key
openssl req -new -key wrong-signing.key -out wrong-signing.csr \
    -subj "/CN=wrong-signer/O=Evil Corp"
openssl x509 -req -in wrong-signing.csr -CA wrong-ca.pem -CAkey wrong-ca.key \
    -CAcreateserial -out wrong-signing.pem -days $DAYS_VALID \
    -extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature")

rm -f *.csr *.srl
echo "=== Done ==="
ls -la *.pem *.key
