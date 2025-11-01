#!/usr/bin/env bash
set -euo pipefail

### ====== User Inputs ======
read -rp "Enter the server FQDN (e.g., testadcs.mydomain.lan): " LEAF_FQDN
read -rp "Enter the organization name (e.g., TestCompany): " ORG

# Trim & checks
LEAF_FQDN="${LEAF_FQDN//[[:space:]]/}"
ORG="${ORG//[[:space:]]/}"
if [[ -z "$LEAF_FQDN" ]]; then echo "Error: FQDN cannot be empty"; exit 1; fi
if [[ -z "$ORG" ]]; then echo "Error: Organization cannot be empty"; exit 1; fi
export LEAF_FQDN

### ====== Variables ======
export CA_DIR="/opt/adcs_python/pki"
export CA_CN="Root CA $ORG"
export COUNTRY="FR"

# CRL URIs
export CRL_URI_ROOT="http://$LEAF_FQDN/crl/root/ca.crl.pem"
export CRL_URI_ICA="http://$LEAF_FQDN/crl/ica/intermediate.crl.pem"

# CERT URIs (assure-toi que /certs/... est servi en HTTP comme /crl/…)
export CERT_URI_ROOT="http://$LEAF_FQDN/certs/root/ca.crt.pem"
export CERT_URI_ICA="http://$LEAF_FQDN/certs/ica/ica.crt.pem"
export CERT_URI_ICA_CHAIN="http://$LEAF_FQDN/certs/ica/ica-chain.pem"
export CERT_URI_LEAF="http://$LEAF_FQDN/certs/ica/$LEAF_FQDN.crt.pem"
export CERT_URI_LEAF_FULLCHAIN="http://$LEAF_FQDN/certs/ica/$LEAF_FQDN.fullchain.pem"

# Intermediate CA
export ICA_CN="Intermediate CA $ORG"

### ====== Arborescence ======
# bases
mkdir -p "$CA_DIR/csr"
mkdir -p "$CA_DIR/newcerts/root" "$CA_DIR/newcerts/ica"
# par CA
mkdir -p "$CA_DIR/certs/root" "$CA_DIR/certs/ica"
mkdir -p "$CA_DIR/crl/root"   "$CA_DIR/crl/ica"
mkdir -p "$CA_DIR/private/root" "$CA_DIR/private/ica"
mkdir -p "$CA_DIR/serial/root"  "$CA_DIR/serial/ica"
# CSR leaf sous ICA
mkdir -p "$CA_DIR/csr/ica"

chmod 700 "$CA_DIR/private/root" "$CA_DIR/private/ica"

# DB / serial
: > "$CA_DIR/index.txt"              # index de la Root
echo 1000 > "$CA_DIR/serial/root/serial"
echo 1000 > "$CA_DIR/serial/root/crlnumber"

: > "$CA_DIR/index_ica.txt"          # index de l'ICA
echo 2000 > "$CA_DIR/serial/ica/serial"
echo 2000 > "$CA_DIR/serial/ica/crlnumber"

### ====== Root CA ======
openssl genrsa -out "$CA_DIR/private/root/ca.key.pem" 4096
chmod 600 "$CA_DIR/private/root/ca.key.pem"

openssl req -x509 -new -sha256 -days 3650 \
  -subj "/C=$COUNTRY/O=$ORG/CN=$CA_CN" \
  -key "$CA_DIR/private/root/ca.key.pem" \
  -addext "basicConstraints=critical,CA:true,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -addext "authorityKeyIdentifier=keyid" \
  -out "$CA_DIR/certs/root/ca.crt.pem"

# Root openssl.cnf (new_certs_dir segmenté en newcerts/root)
cat > "$CA_DIR/openssl.cnf" <<EOF
[ ca ]
default_ca = myca

[ myca ]
dir               = $CA_DIR
database          = \$dir/index.txt
new_certs_dir     = \$dir/newcerts/root
private_key       = \$dir/private/root/ca.key.pem
certificate       = \$dir/certs/root/ca.crt.pem
serial            = \$dir/serial/root/serial
crlnumber         = \$dir/serial/root/crlnumber
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

# Profil pour signer l'intermédiaire (alimente newcerts/root + index Root)
[ v3_intermediate ]
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
crlDistributionPoints = URI:$CRL_URI_ROOT
EOF

# CRL Root
openssl ca -config "$CA_DIR/openssl.cnf" -gencrl -out "$CA_DIR/crl/root/ca.crl.pem"

### ====== Intermediate CA ======
openssl genrsa -out "$CA_DIR/private/ica/ica.key.pem" 4096
chmod 600 "$CA_DIR/private/ica/ica.key.pem"

openssl req -new -sha256 \
  -subj "/C=$COUNTRY/O=$ORG/CN=$ICA_CN" \
  -key "$CA_DIR/private/ica/ica.key.pem" \
  -out "$CA_DIR/csr/ica.csr.pem"

# Signature de l'ICA par la Root via 'openssl ca' (alimente newcerts/root + index.txt Root)
openssl ca -batch -config "$CA_DIR/openssl.cnf" \
  -in "$CA_DIR/csr/ica.csr.pem" \
  -out "$CA_DIR/certs/ica/ica.crt.pem" \
  -extensions v3_intermediate \
  -days 3650 -notext

# Chaîne intermédiaire
cat "$CA_DIR/certs/ica/ica.crt.pem" "$CA_DIR/certs/root/ca.crt.pem" > "$CA_DIR/certs/ica/ica-chain.pem"

# openssl.cnf ICA
cat > "$CA_DIR/openssl-ica.cnf" <<EOF
[ ca ]
default_ca = myica

[ myica ]
dir               = $CA_DIR
database          = \$dir/index_ica.txt
new_certs_dir     = \$dir/newcerts/ica
private_key       = \$dir/private/ica/ica.key.pem
certificate       = \$dir/certs/ica/ica.crt.pem
serial            = \$dir/serial/ica/serial
crlnumber         = \$dir/serial/ica/crlnumber
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
# SAN injecté depuis l'environnement au moment de la signature
subjectAltName = DNS:\${ENV::LEAF_FQDN}
# AIA pour aider les clients à récupérer l'ICA
authorityInfoAccess = caIssuers;URI:$CERT_URI_ICA
EOF

# CRL ICA
openssl ca -config "$CA_DIR/openssl-ica.cnf" -gencrl -out "$CA_DIR/crl/ica/intermediate.crl.pem"

### ====== Leaf (directement sous .../ica) ======
# clé/CSR (SAN ajouté lors de la signature via v3_server)
openssl genrsa -out "$CA_DIR/private/ica/$LEAF_FQDN.key.pem" 2048
chmod 600 "$CA_DIR/private/ica/$LEAF_FQDN.key.pem"

openssl req -new -sha256 \
  -subj "/C=$COUNTRY/O=$ORG/CN=$LEAF_FQDN" \
  -key "$CA_DIR/private/ica/$LEAF_FQDN.key.pem" \
  -out "$CA_DIR/csr/ica/$LEAF_FQDN.csr.pem"

# Signature par l'ICA (alimente newcerts/ica + index_ica)
openssl ca -batch -config "$CA_DIR/openssl-ica.cnf" \
  -in  "$CA_DIR/csr/ica/$LEAF_FQDN.csr.pem" \
  -out "$CA_DIR/certs/ica/$LEAF_FQDN.crt.pem" \
  -extensions v3_server

# fullchain leaf
cat "$CA_DIR/certs/ica/$LEAF_FQDN.crt.pem" "$CA_DIR/certs/ica/ica.crt.pem" > "$CA_DIR/certs/ica/$LEAF_FQDN.fullchain.pem"

### ====== Vérifications ======
openssl verify -CAfile "$CA_DIR/certs/ica/ica-chain.pem" "$CA_DIR/certs/ica/$LEAF_FQDN.crt.pem"

openssl x509 -in "$CA_DIR/certs/ica/$LEAF_FQDN.crt.pem" -noout -text | sed -n '/X509v3 extensions:/,/Signature Algorithm/p'

echo "OK: Root, Intermediate, CRLs, and Leaf generated."
echo " - Root CA cert        : $CA_DIR/certs/root/ca.crt.pem        (URI: $CERT_URI_ROOT)"
echo " - Intermediate cert   : $CA_DIR/certs/ica/ica.crt.pem        (URI: $CERT_URI_ICA)"
echo " - ICA chain           : $CA_DIR/certs/ica/ica-chain.pem      (URI: $CERT_URI_ICA_CHAIN)"
echo " - Leaf key            : $CA_DIR/private/ica/$LEAF_FQDN.key.pem"
echo " - Leaf CSR            : $CA_DIR/csr/ica/$LEAF_FQDN.csr.pem"
echo " - Leaf cert           : $CA_DIR/certs/ica/$LEAF_FQDN.crt.pem (URI: $CERT_URI_LEAF)"
echo " - Leaf fullchain      : $CA_DIR/certs/ica/$LEAF_FQDN.fullchain.pem (URI: $CERT_URI_LEAF_FULLCHAIN)"
echo " - CRL Root            : $CA_DIR/crl/root/ca.crl.pem          (URI: $CRL_URI_ROOT)"
echo " - CRL Intermediate    : $CA_DIR/crl/ica/intermediate.crl.pem (URI: $CRL_URI_ICA)"
echo " - Newcerts Root (ICA) : $CA_DIR/newcerts/root"
echo " - Newcerts ICA (Leaf) : $CA_DIR/newcerts/ica"

