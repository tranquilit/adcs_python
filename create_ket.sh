#!/usr/bin/env bash
set -euo pipefail

# Self-signed "KET" certificate (CAExchange-style) for CES RST/KET.
# Compatible approach: req -> CSR, then x509 -> self-sign with -extfile.

OUT_DIR="/var/lib/adcs/pki/ket-self"
KET_CN="Cert KET"
KET_DAYS=3650  # 10 years
KEY_BITS=2048

mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR" || true

KET_KEY="$OUT_DIR/ket.key.pem"
KET_CSR="$OUT_DIR/ket.csr.pem"
KET_CERT="$OUT_DIR/ket.crt.pem"
KET_EXTFILE="$OUT_DIR/openssl-ket-ext.cnf"

# Extensions Windows expects for CAExchange-like KET
cat > "$KET_EXTFILE" <<'EOF'
[ v3_ket ]
basicConstraints = CA:FALSE
keyUsage = critical,keyEncipherment
extendedKeyUsage = 1.3.6.1.4.1.311.21.5
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer

# Microsoft "Certificate Template Name" (szOID_ENROLL_CERTTYPE)
1.3.6.1.4.1.311.20.2 = ASN1:SEQUENCE:ket_template_name

# Microsoft "Application Policies" extension
1.3.6.1.4.1.311.21.10 = ASN1:SEQUENCE:ket_app_policies

[ ket_template_name ]
name = UTF8:CAExchange

[ ket_app_policies ]
policy0 = SEQUENCE:ket_policy0

[ ket_policy0 ]
policyIdentifier = OID:1.3.6.1.4.1.311.21.5
EOF

echo "Wrote extfile: $KET_EXTFILE"

# RSA key
if [[ -f "$KET_KEY" ]]; then
  echo "KET key already exists: $KET_KEY"
else
  openssl genrsa -out "$KET_KEY" "$KEY_BITS"
  chmod 600 "$KET_KEY"
  echo "Generated KET key: $KET_KEY"
fi

# CSR
openssl req -new \
  -subj "/C=FR/O=KET/CN=$KET_CN" \
  -key "$KET_KEY" \
  -out "$KET_CSR"
echo "Generated KET CSR: $KET_CSR"

# Self-sign CSR -> cert with extensions
openssl x509 -req -sha256 \
  -in "$KET_CSR" \
  -signkey "$KET_KEY" \
  -days "$KET_DAYS" \
  -extfile "$KET_EXTFILE" \
  -extensions v3_ket \
  -out "$KET_CERT"
echo "Created self-signed KET cert: $KET_CERT"

echo
echo "Quick check:"
openssl x509 -in "$KET_CERT" -noout -text | sed -n '/X509v3 extensions:/,/Signature Algorithm/p' || true

echo
echo "OK: Self-signed KET ready."
echo " - Subject CN     : $KET_CN"
echo " - Key            : $KET_KEY"
echo " - CSR            : $KET_CSR"
echo " - Cert (PEM)     : $KET_CERT"
echo

