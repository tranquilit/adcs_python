#!/usr/bin/env bash
set -euo pipefail

### ====== User Inputs ======
read -rp "Enter the server FQDN (e.g., testadcs.mydomain.lan): " LEAF_FQDN
read -rp "Enter the organization name (e.g., TestCompany): " ORG

### ====== Variables ======
export CA_DIR="/opt/adcs_python/pki"         # flat CA directory
export CA_CN="Root CA"
export COUNTRY="FR"

# CRL URIs
export CRL_URI_ROOT="http://$LEAF_FQDN/crl/ca.crl.pem"          # Root CA CRL
export CRL_URI_ICA="http://$LEAF_FQDN/crl/intermediate.crl.pem" # Intermediate CA CRL

# Intermediate CA
export ICA_CN="Intermediate CA"

### ====== Standard Flat Structure ======
mkdir -p "$CA_DIR"/{certs,crl,newcerts,private,csr}
chmod 700 "$CA_DIR/private"

# Root DB
: > "$CA_DIR/index.txt"
echo 1000 > "$CA_DIR/serial"
echo 1000 > "$CA_DIR/crlnumber"

# Intermediate DB (separate but same directory)
: > "$CA_DIR/index_ica.txt"
echo 2000 > "$CA_DIR/serial_ica"
echo 2000 > "$CA_DIR/crlnumber_ica"

### ====== Root CA ======
openssl genrsa -out "$CA_DIR/private/ca.key.pem" 4096
chmod 600 "$CA_DIR/private/ca.key.pem"

openssl req -x509 -new -sha256 -days 3650 \
  -subj "/C=$COUNTRY/O=$ORG/CN=$CA_CN" \
  -key "$CA_DIR/private/ca.key.pem" \
  -addext "basicConstraints=critical,CA:true,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -addext "authorityKeyIdentifier=keyid" \
  -out "$CA_DIR/certs/ca.crt.pem"

# Root openssl.cnf
cat > "$CA_DIR/openssl.cnf" <<EOF
[ ca ]
default_ca = myca

[ myca ]
dir               = $CA_DIR
database          = \$dir/index.txt
new_certs_dir     = \$dir/newcerts
private_key       = \$dir/private/ca.key.pem
certificate       = \$dir/certs/ca.crt.pem
serial            = \$dir/serial
crlnumber         = \$dir/crlnumber
default_md        = sha256
default_days      = 3650
default_crl_days  = 30
unique_subject    = no
policy            = policy_loose

[ policy_loose ]
commonName              = supplied
stateOrProvinceName     = optional
countryName             = optional
organizationName        = optional
organizationalUnitName  = optional
emailAddress            = optional
EOF

# Generate Root CRL
openssl ca -config "$CA_DIR/openssl.cnf" -gencrl -out "$CA_DIR/crl/ca.crl.pem"

### ====== Intermediate CA ======
openssl genrsa -out "$CA_DIR/private/ica.key.pem" 4096
chmod 600 "$CA_DIR/private/ica.key.pem"

openssl req -new -sha256 \
  -subj "/C=$COUNTRY/O=$ORG/CN=$ICA_CN" \
  -key "$CA_DIR/private/ica.key.pem" \
  -out "$CA_DIR/csr/ica.csr.pem"

# Sign Intermediate with Root
openssl x509 -req -sha256 -days 3650 \
  -in "$CA_DIR/csr/ica.csr.pem" \
  -CA "$CA_DIR/certs/ca.crt.pem" \
  -CAkey "$CA_DIR/private/ca.key.pem" \
  -CAserial "$CA_DIR/serial" \
  -out "$CA_DIR/certs/ica.crt.pem" \
  -extfile <(printf "%s\n" \
    "basicConstraints=critical,CA:true,pathlen:0" \
    "keyUsage=critical,keyCertSign,cRLSign" \
    "subjectKeyIdentifier=hash" \
    "authorityKeyIdentifier=keyid,issuer" \
    "crlDistributionPoints=URI:$CRL_URI_ROOT" \
  )

# Intermediate chain
cat "$CA_DIR/certs/ica.crt.pem" "$CA_DIR/certs/ca.crt.pem" > "$CA_DIR/certs/ica-chain.pem"

# Intermediate openssl.cnf (for signing leaf certs)
cat > "$CA_DIR/openssl-ica.cnf" <<EOF
[ ca ]
default_ca = myica

[ myica ]
dir               = $CA_DIR
database          = \$dir/index_ica.txt
new_certs_dir     = \$dir/newcerts
private_key       = \$dir/private/ica.key.pem
certificate       = \$dir/certs/ica.crt.pem
serial            = \$dir/serial_ica
crlnumber         = \$dir/crlnumber_ica
default_md        = sha256
default_days      = 825
default_crl_days  = 30
unique_subject    = no
policy            = policy_loose
copy_extensions   = copy

[ policy_loose ]
commonName              = supplied
stateOrProvinceName     = optional
countryName             = optional
organizationName        = optional
organizationalUnitName  = optional
emailAddress            = optional

[ v3_server ]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth,clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
crlDistributionPoints = URI:$CRL_URI_ICA
EOF

# Intermediate CRL
openssl ca -config "$CA_DIR/openssl-ica.cnf" -gencrl -out "$CA_DIR/crl/intermediate.crl.pem"

### ====== Leaf Certificate ======
openssl genrsa -out "$CA_DIR/private/$LEAF_FQDN.key.pem" 2048
chmod 600 "$CA_DIR/private/$LEAF_FQDN.key.pem"

openssl req -new -sha256 \
  -subj "/C=$COUNTRY/O=$ORG/CN=$LEAF_FQDN" \
  -key "$CA_DIR/private/$LEAF_FQDN.key.pem" \
  -out "$CA_DIR/csr/$LEAF_FQDN.csr.pem" \
  -addext "subjectAltName=DNS:$LEAF_FQDN"

# Sign leaf with ICA
openssl ca -batch -config "$CA_DIR/openssl-ica.cnf" \
  -in "$CA_DIR/csr/$LEAF_FQDN.csr.pem" \
  -out "$CA_DIR/certs/$LEAF_FQDN.crt.pem" \
  -extensions v3_server

# Leaf fullchain
cat "$CA_DIR/certs/$LEAF_FQDN.crt.pem" "$CA_DIR/certs/ica.crt.pem" > "$CA_DIR/certs/$LEAF_FQDN.fullchain.pem"

### ====== Verification ======
openssl verify -CAfile "$CA_DIR/certs/ica-chain.pem" "$CA_DIR/certs/$LEAF_FQDN.crt.pem"

openssl x509 -in "$CA_DIR/certs/$LEAF_FQDN.crt.pem" -noout -text | sed -n '/X509v3 extensions:/,/Signature Algorithm/p'

echo "OK: Root, Intermediate, CRLs, and Leaf generated (flat structure)."
echo " - Root CA      : $CA_DIR/certs/ca.crt.pem"
echo " - Intermediate : $CA_DIR/certs/ica.crt.pem"
echo " - Leaf         : $CA_DIR/certs/$LEAF_FQDN.crt.pem"
echo " - Leaf fullchain : $CA_DIR/certs/$LEAF_FQDN.fullchain.pem"
echo " - CRL Root     : $CA_DIR/crl/ca.crl.pem    (URI: $CRL_URI_ROOT)"
echo " - CRL Intermediate : $CA_DIR/crl/intermediate.crl.pem  (URI: $CRL_URI_ICA)"
