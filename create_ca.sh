export CA_DIR="/opt/adcs_python/pki"
export CA_CN="Test CA"
export ORG="Test"
export COUNTRY="FR"
export CRL_URI="http://testadcs.mydomain.lan/crl/ca.crl.pem"
export LEAF_FQDN="testadcs.mydomain.lan"

mkdir -p "$CA_DIR"/{certs,crl,newcerts,private,csr}
chmod 700 "$CA_DIR/private"
: > "$CA_DIR/index.txt"
echo 1000 > "$CA_DIR/serial"
echo 1000 > "$CA_DIR/crlnumber"

openssl genrsa -out "$CA_DIR/private/ca.key.pem" 4096
chmod 600 "$CA_DIR/private/ca.key.pem"

openssl req -x509 -new -sha256 -days 3650 \
  -subj "/C=$COUNTRY/O=$ORG/CN=$CA_CN" \
  -key "$CA_DIR/private/ca.key.pem" \
  -addext "basicConsints=critical,CA:true,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -addext "authorityKeyIdentifier=keyid" \
  -out "$CA_DIR/certs/ca.crt.pem"

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


openssl ca -config "$CA_DIR/openssl.cnf" -gencrl -out "$CA_DIR/crl/ca.crl.pem"


openssl genrsa -out "$CA_DIR/private/$LEAF_FQDN.key.pem" 2048
chmod 600 "$CA_DIR/private/$LEAF_FQDN.key.pem"

openssl req -new -sha256 \
  -subj "/C=$COUNTRY/O=$ORG/CN=$LEAF_FQDN" \
  -key "$CA_DIR/private/$LEAF_FQDN.key.pem" \
  -out "$CA_DIR/csr/$LEAF_FQDN.csr.pem"


openssl x509 -req -sha256 -days 825 \
  -in "$CA_DIR/csr/$LEAF_FQDN.csr.pem" \
  -CA "$CA_DIR/certs/ca.crt.pem" \
  -CAkey "$CA_DIR/private/ca.key.pem" \
  -CAserial "$CA_DIR/serial" \
  -out "$CA_DIR/certs/$LEAF_FQDN.crt.pem" \
  -extfile <(printf "%s\n" \
    "basicConsints=CA:FALSE" \
    "keyUsage=critical,digitalSignature,keyEncipherment" \
    "extendedKeyUsage=serverAuth,clientAuth" \
    "subjectKeyIdentifier=hash" \
    "authorityKeyIdentifier=keyid,issuer" \
    "subjectAltName=DNS:$LEAF_FQDN" \
    "crlDistributionPoints=URI:$CRL_URI" \
  )


openssl x509 -in "$CA_DIR/certs/$LEAF_FQDN.crt.pem" -noout -text | sed -n '/X509v3 extensions:/,/Signature Algorithm/p'

