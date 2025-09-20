#!/usr/bin/env bash
set -euo pipefail

### ====== Variables ======
export CA_DIR="/opt/adcs_python/pki"                # répertoire unique (à plat)
export CA_CN="Test CA"
export ORG="Test"
export COUNTRY="FR"

# URI CRL
export CRL_URI_ROOT="http://testadcs.mydomain.lan/crl/ca.crl.pem"            # CRL de la RACINE
export CRL_URI_ICA="http://testadcs.mydomain.lan/crl/intermediate.crl.pem"   # CRL de l'INTERMÉDIAIRE

# Intermédiaire
export ICA_CN="Test Intermediate CA"

# Certificat serveur (leaf)
export LEAF_FQDN="testadcs.mydomain.lan"

### ====== Arbo standard à plat ======
mkdir -p "$CA_DIR"/{certs,crl,newcerts,private,csr}
chmod 700 "$CA_DIR/private"

# DB Root
: > "$CA_DIR/index.txt"
echo 1000 > "$CA_DIR/serial"
echo 1000 > "$CA_DIR/crlnumber"

# DB ICA (fichiers séparés mais même répertoire)
: > "$CA_DIR/index_ica.txt"
echo 2000 > "$CA_DIR/serial_ica"
echo 2000 > "$CA_DIR/crlnumber_ica"

### ====== Root CA ======
openssl genrsa -out "$CA_DIR/private/ca.key.pem" 4096
chmod 600 "$CA_DIR/private/ca.key.pem"

# pathlen:1 pour autoriser UN niveau d'intermédiaire
openssl req -x509 -new -sha256 -days 3650 \
  -subj "/C=$COUNTRY/O=$ORG/CN=$CA_CN" \
  -key "$CA_DIR/private/ca.key.pem" \
  -addext "basicConstraints=critical,CA:true,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -addext "authorityKeyIdentifier=keyid" \
  -out "$CA_DIR/certs/ca.crt.pem"

# openssl.cnf de la ROOT (principalement pour la CRL root)
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

# CRL de la root
openssl ca -config "$CA_DIR/openssl.cnf" -gencrl -out "$CA_DIR/crl/ca.crl.pem"

### ====== Intermédiaire (fichiers à plat) ======
# Clé + CSR de l'ICA
openssl genrsa -out "$CA_DIR/private/ica.key.pem" 4096
chmod 600 "$CA_DIR/private/ica.key.pem"

openssl req -new -sha256 \
  -subj "/C=$COUNTRY/O=$ORG/CN=$ICA_CN" \
  -key "$CA_DIR/private/ica.key.pem" \
  -out "$CA_DIR/csr/ica.csr.pem"

# Signature de l'ICA par la ROOT
# IMPORTANT : la CRL pointée dans le cert ICA est celle de la ROOT (émetteur)
openssl x509 -req -sha256 -days 3650 \
  -in  "$CA_DIR/csr/ica.csr.pem" \
  -CA  "$CA_DIR/certs/ca.crt.pem" \
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

# Chaîne ICA (ICA + ROOT)
cat "$CA_DIR/certs/ica.crt.pem" "$CA_DIR/certs/ca.crt.pem" > "$CA_DIR/certs/ica-chain.pem"

# openssl-ica.cnf : config dédiée à l’ICA (DB séparée), utilisée pour signer les LEAF
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
# IMPORTANT : pour les LEAF émis par l'ICA, on pointe vers la CRL de l'ICA (émetteur direct)
crlDistributionPoints = URI:$CRL_URI_ICA
# Pour forcer les SAN ici (au lieu du CSR), décommentez:
# subjectAltName = @alt_names
# [ alt_names ]
# DNS.1 = $LEAF_FQDN
EOF

# CRL de l'ICA
openssl ca -config "$CA_DIR/openssl-ica.cnf" -gencrl -out "$CA_DIR/crl/intermediate.crl.pem"

### ====== LEAF signé par l’ICA ======
# Clé + CSR (avec SAN)
openssl genrsa -out "$CA_DIR/private/$LEAF_FQDN.key.pem" 2048
chmod 600 "$CA_DIR/private/$LEAF_FQDN.key.pem"

openssl req -new -sha256 \
  -subj "/C=$COUNTRY/O=$ORG/CN=$LEAF_FQDN" \
  -key "$CA_DIR/private/$LEAF_FQDN.key.pem" \
  -out "$CA_DIR/csr/$LEAF_FQDN.csr.pem" \
  -addext "subjectAltName=DNS:$LEAF_FQDN"

# Signature du LEAF par l'ICA (profil serveur -> CRL de l'ICA)
openssl ca -batch -config "$CA_DIR/openssl-ica.cnf" \
  -in "$CA_DIR/csr/$LEAF_FQDN.csr.pem" \
  -out "$CA_DIR/certs/$LEAF_FQDN.crt.pem" \
  -extensions v3_server

# Chaîne pour serveur (leaf + ICA)
cat "$CA_DIR/certs/$LEAF_FQDN.crt.pem" "$CA_DIR/certs/ica.crt.pem" > "$CA_DIR/certs/$LEAF_FQDN.fullchain.pem"

### ====== Vérifs & infos ======
# Vérifie la chaîne du LEAF avec la chaîne ICA (ICA + ROOT)
openssl verify -CAfile "$CA_DIR/certs/ica-chain.pem" "$CA_DIR/certs/$LEAF_FQDN.crt.pem"

# Affiche les extensions du LEAF
openssl x509 -in "$CA_DIR/certs/$LEAF_FQDN.crt.pem" -noout -text | sed -n '/X509v3 extensions:/,/Signature Algorithm/p'

echo "OK : Root, ICA, CRL root/ICA et Leaf générés (structure à plat)."
echo " - Root CA      : $CA_DIR/certs/ca.crt.pem"
echo " - ICA          : $CA_DIR/certs/ica.crt.pem"
echo " - Leaf         : $CA_DIR/certs/$LEAF_FQDN.crt.pem"
echo " - Leaf chain   : $CA_DIR/certs/$LEAF_FQDN.fullchain.pem"
echo " - CRL Root     : $CA_DIR/crl/ca.crl.pem            (URI: $CRL_URI_ROOT)"
echo " - CRL ICA      : $CA_DIR/crl/intermediate.crl.pem  (URI: $CRL_URI_ICA)"

