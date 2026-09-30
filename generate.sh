#!/usr/bin/env bash
# CryptoInventory POC - sample crypto material generator
# ALL MATERIAL IS FOR TESTING ONLY. Never use these keys/certs in any real system.
# Requires: openssl (3.x; 3.5+ adds PQC), python3 + cryptography (SSH keys), optional: keytool, gpg
set -euo pipefail
OUT="${1:-./materials}"
PASS="Test@1234"
mkdir -p "$OUT"; cd "$OUT"
mkdir -p certificates/{pki-chain,ecdsa,eddsa,weak,formats,csr,crl} keys/{asymmetric,symmetric} ssh pgp pqc keystores

# Some weak algorithms need legacy security level to be signed/used
LEGACY_CNF=$(mktemp); cat > "$LEGACY_CNF" <<CNF
openssl_conf = openssl_init
[openssl_init]
ssl_conf = ssl_sect
[ssl_sect]
system_default = sys
[sys]
CipherString = DEFAULT@SECLEVEL=0
[req]
distinguished_name = dn
[dn]
CNF

ext() { # $1 = file, $2.. = lines
  local f=$1; shift; printf '%s\n' "$@" > "$f"; }

echo "[*] PKI chain (RSA root -> intermediate -> leaf)"
cd certificates/pki-chain
openssl req -x509 -newkey rsa:4096 -sha384 -nodes -days 7300 -keyout root-ca.key -out root-ca.crt \
  -subj "/C=IN/O=CryptoInventory Test/CN=CI Test Root CA R1" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -newkey rsa:3072 -nodes -keyout intermediate-ca.key -out intermediate-ca.csr \
  -subj "/C=IN/O=CryptoInventory Test/CN=CI Test Issuing CA I1" 2>/dev/null
ext int.ext "basicConstraints=critical,CA:TRUE,pathlen:0" "keyUsage=critical,keyCertSign,cRLSign" \
  "crlDistributionPoints=URI:http://crl.ci.test/i1.crl" "authorityInfoAccess=OCSP;URI:http://ocsp.ci.test"
openssl x509 -req -in intermediate-ca.csr -CA root-ca.crt -CAkey root-ca.key -CAcreateserial -sha256 \
  -days 3650 -extfile int.ext -out intermediate-ca.crt 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout server-rsa2048.key -out server-rsa2048.csr \
  -subj "/C=IN/O=CryptoInventory Test/CN=app.ci.test" 2>/dev/null
ext leaf.ext "basicConstraints=CA:FALSE" "keyUsage=critical,digitalSignature,keyEncipherment" \
  "extendedKeyUsage=serverAuth,clientAuth" "subjectAltName=DNS:app.ci.test,DNS:www.app.ci.test,IP:10.0.0.10"
openssl x509 -req -in server-rsa2048.csr -CA intermediate-ca.crt -CAkey intermediate-ca.key -CAcreateserial \
  -sha256 -days 397 -extfile leaf.ext -out server-rsa2048.crt 2>/dev/null
# client auth + code signing + email (S/MIME) leaves
for kind in client codesign smime; do
  case $kind in
    client)   eku="clientAuth"; san="email:user01@ci.test";;
    codesign) eku="codeSigning"; san="DNS:build.ci.test";;
    smime)    eku="emailProtection"; san="email:alice@ci.test";;
  esac
  openssl req -newkey rsa:3072 -nodes -keyout $kind.key -out $kind.csr -subj "/O=CryptoInventory Test/CN=CI $kind" 2>/dev/null
  ext $kind.ext "basicConstraints=CA:FALSE" "keyUsage=critical,digitalSignature" "extendedKeyUsage=$eku" "subjectAltName=$san"
  openssl x509 -req -in $kind.csr -CA intermediate-ca.crt -CAkey intermediate-ca.key -CAcreateserial -sha256 \
    -days 365 -extfile $kind.ext -out $kind.crt 2>/dev/null
done
cat server-rsa2048.crt intermediate-ca.crt root-ca.crt > fullchain.pem
rm -f *.ext *.srl
cd ../..

echo "[*] ECDSA certs"
cd certificates/ecdsa
for c in prime256v1:sha256 secp384r1:sha384 secp521r1:sha512; do
  curve=${c%%:*}; md=${c##*:}
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:$curve -$md -nodes -days 365 \
    -keyout ecdsa-$curve.key -out ecdsa-$curve.crt -subj "/O=CryptoInventory Test/CN=ecdsa-$curve.ci.test" \
    -addext "subjectAltName=DNS:ecdsa-$curve.ci.test" 2>/dev/null
done
cd ../..

echo "[*] EdDSA certs"
cd certificates/eddsa
for a in ed25519 ed448; do
  openssl req -x509 -newkey $a -nodes -days 365 -keyout $a.key -out $a.crt \
    -subj "/O=CryptoInventory Test/CN=$a.ci.test" 2>/dev/null
done
cd ../..

echo "[*] Weak / non-compliant certs (discovery should flag these)"
cd certificates/weak
W="-subj /O=CryptoInventory_Test_WEAK"
openssl req -x509 -newkey rsa:1024 -sha256 -nodes -days 365 -keyout rsa1024.key -out rsa1024.crt $W/CN=rsa1024.ci.test 2>/dev/null
OPENSSL_CONF=$LEGACY_CNF openssl req -x509 -newkey rsa:2048 -sha1 -nodes -days 365 -keyout sha1-signed.key -out sha1-signed.crt $W/CN=sha1.ci.test 2>/dev/null
OPENSSL_CONF=$LEGACY_CNF openssl req -x509 -newkey rsa:2048 -md5 -nodes -days 365 -keyout md5-signed.key -out md5-signed.crt $W/CN=md5.ci.test 2>/dev/null || echo "   (md5 signing not allowed by this OpenSSL, skipped)"
# expired: backdate using x509 -not_before/-not_after is 3.4+, so use 'ca'-less trick via faketime-free python
python3 - <<'PY'
import datetime as dt
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
def mk(name, nb, na, san=True, cn=None):
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME,"CryptoInventory Test WEAK"),
                   x509.NameAttribute(NameOID.COMMON_NAME, cn or f"{name}.ci.test")])
    b = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(nb).not_valid_after(na))
    if san: b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(cn or f"{name}.ci.test")]), False)
    c = b.sign(k, hashes.SHA256())
    open(f"{name}.crt","wb").write(c.public_bytes(serialization.Encoding.PEM))
    open(f"{name}.key","wb").write(k.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
now = dt.datetime.now(dt.timezone.utc); d = dt.timedelta(days=1)
mk("expired", now-800*d, now-30*d)
mk("expiring-in-7-days", now-358*d, now+7*d)
mk("not-yet-valid", now+30*d, now+400*d)
mk("long-validity-10y", now, now+3650*d)          # > 398 days, violates CA/B BR for TLS
mk("no-san", now, now+365*d, san=False)
mk("wildcard", now, now+365*d, cn="*.ci.test")
PY
cd ../..

echo "[*] Certificate formats (PEM, DER, PKCS#7, PKCS#12)"
cd certificates/formats
P=../pki-chain
cp $P/server-rsa2048.crt server.pem
openssl x509 -in $P/server-rsa2048.crt -outform DER -out server.der
cp server.der server.cer
openssl crl2pkcs7 -nocrl -certfile $P/fullchain.pem -out chain.p7b
openssl crl2pkcs7 -nocrl -certfile $P/fullchain.pem -outform DER -out chain-der.p7b
openssl pkcs12 -export -in $P/server-rsa2048.crt -inkey $P/server-rsa2048.key -certfile $P/intermediate-ca.crt \
  -name server -passout pass:$PASS -out server-aes256.pfx
cp server-aes256.pfx server-aes256.p12
openssl pkcs12 -export -in $P/server-rsa2048.crt -inkey $P/server-rsa2048.key -legacy \
  -passout pass:$PASS -out server-legacy-3des.pfx 2>/dev/null || echo "   (legacy pfx skipped)"
cd ../..

echo "[*] CSRs and CRL"
cp certificates/pki-chain/*.csr certificates/csr/
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout certificates/csr/ec-p256.key \
  -out certificates/csr/ec-p256.csr -subj "/O=CryptoInventory Test/CN=csr-ec.ci.test" 2>/dev/null
cd certificates/crl
mkdir -p db; touch db/index.txt; echo 1000 > db/crlnumber
cat > ca.cnf <<CNF
[ca]
default_ca = CA
[CA]
database = db/index.txt
crlnumber = db/crlnumber
default_md = sha256
default_crl_days = 30
CNF
openssl ca -config ca.cnf -gencrl -keyfile ../pki-chain/intermediate-ca.key -cert ../pki-chain/intermediate-ca.crt -out i1.crl 2>/dev/null
openssl crl -in i1.crl -outform DER -out i1-der.crl
rm -rf db ca.cnf
cd ../..

echo "[*] Asymmetric keys in many encodings"
cd keys/asymmetric
openssl genrsa -traditional -out rsa2048-pkcs1.pem 2048 2>/dev/null
openssl pkey -in rsa2048-pkcs1.pem -out rsa2048-pkcs8.pem
openssl pkcs8 -topk8 -in rsa2048-pkcs1.pem -v2 aes-256-cbc -passout pass:$PASS -out rsa2048-pkcs8-encrypted.pem
openssl genrsa -aes256 -passout pass:$PASS -out rsa4096-traditional-encrypted.pem 4096 2>/dev/null
openssl pkey -in rsa2048-pkcs1.pem -outform DER -out rsa2048-pkcs8.der
openssl pkey -in rsa2048-pkcs1.pem -pubout -out rsa2048-public.pem
openssl rsa -in rsa2048-pkcs1.pem -RSAPublicKey_out -out rsa2048-public-pkcs1.pem 2>/dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp256k1 -out ec-secp256k1.pem
openssl ecparam -name prime256v1 -genkey -noout -out ec-p256-sec1.pem
openssl genpkey -algorithm X25519 -out x25519.pem
openssl genpkey -algorithm X448 -out x448.pem
openssl genpkey -algorithm ed25519 -out ed25519.pem
OPENSSL_CONF=$LEGACY_CNF openssl dsaparam -genkey -out dsa1024-WEAK.pem 1024 2>/dev/null
openssl dhparam -out dh2048.pem 2048 2>/dev/null
openssl dhparam -out dh1024-WEAK.pem 1024 2>/dev/null || true
cd ../..

echo "[*] Symmetric keys / secrets"
cd keys/symmetric
openssl rand -hex 16 > aes128.key.hex
openssl rand -hex 32 > aes256.key.hex
openssl rand -out aes256.key.bin 32
openssl rand -hex 8  > des-WEAK.key.hex
openssl rand -hex 24 > 3des-WEAK.key.hex
openssl rand -base64 64 > hmac-sha256-secret.b64
openssl rand -hex 32 > chacha20.key.hex
echo "Sample encrypted payload" | openssl enc -aes-256-cbc -pbkdf2 -pass pass:$PASS -out sample-aes256-cbc.enc
cd ../..

echo "[*] SSH keys (OpenSSH format)"
python3 - <<'PY'
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
keys = {"id_rsa": rsa.generate_private_key(65537, 3072),
        "id_rsa1024_WEAK": rsa.generate_private_key(65537, 1024),
        "id_ecdsa": ec.generate_private_key(ec.SECP256R1()),
        "id_ed25519": ed25519.Ed25519PrivateKey.generate()}
auth = []
for n, k in keys.items():
    open(f"ssh/{n}","wb").write(k.private_bytes(s.Encoding.PEM if n.startswith("id_rsa1024") else s.Encoding.PEM,
        s.PrivateFormat.OpenSSH, s.NoEncryption()))
    pub = k.public_key().public_bytes(s.Encoding.OpenSSH, s.PublicFormat.OpenSSH).decode()+f" {n}@ci.test"
    open(f"ssh/{n}.pub","w").write(pub+"\n"); auth.append(pub)
open("ssh/authorized_keys","w").write("\n".join(auth)+"\n")
open("ssh/known_hosts","w").write("\n".join("bastion.ci.test "+a.rsplit(" ",1)[0] for a in auth)+"\n")
PY
chmod 600 ssh/id_* 2>/dev/null || true

echo "[*] PGP keys"
if command -v gpg >/dev/null; then
  GH=$(mktemp -d)
  gpg --homedir "$GH" --batch --pinentry-mode loopback --passphrase "$PASS" \
      --quick-gen-key "CI Test Signer <pgp@ci.test>" rsa3072 sign,cert 1y 2>/dev/null
  FPR=$(gpg --homedir "$GH" --list-keys --with-colons | awk -F: '/^fpr/{print $10; exit}')
  gpg --homedir "$GH" --batch --pinentry-mode loopback --passphrase "$PASS" --quick-add-key "$FPR" cv25519 encr 1y 2>/dev/null
  gpg --homedir "$GH" --armor --export > pgp/ci-test-public.asc
  gpg --homedir "$GH" --batch --pinentry-mode loopback --passphrase "$PASS" --armor --export-secret-keys > pgp/ci-test-private.asc
  rm -rf "$GH"
fi

echo "[*] Java keystores"
if command -v keytool >/dev/null; then
  keytool -genkeypair -alias app -keyalg RSA -keysize 2048 -dname "CN=jks.ci.test,O=CryptoInventory Test" \
    -validity 365 -storetype JKS -keystore keystores/app.jks -storepass $PASS -keypass $PASS 2>/dev/null
  keytool -genkeypair -alias app-ec -keyalg EC -groupname secp384r1 -dname "CN=p12.ci.test,O=CryptoInventory Test" \
    -validity 365 -storetype PKCS12 -keystore keystores/app.p12 -storepass $PASS 2>/dev/null
  keytool -importcert -noprompt -alias ci-root -file certificates/pki-chain/root-ca.crt \
    -keystore keystores/truststore.jks -storetype JKS -storepass $PASS 2>/dev/null
  keytool -genseckey -alias aes-key -keyalg AES -keysize 256 -storetype JCEKS \
    -keystore keystores/secrets.jceks -storepass $PASS -keypass $PASS 2>/dev/null
fi

echo "[*] Post-quantum (needs OpenSSL 3.5+)"
if openssl list -signature-algorithms 2>/dev/null | grep -qi "ML-DSA"; then
  cd pqc
  for a in ML-DSA-44 ML-DSA-65 ML-DSA-87 SLH-DSA-SHA2-128s; do
    openssl req -x509 -newkey $a -nodes -days 365 -keyout $a.key -out $a.crt -subj "/O=CryptoInventory Test/CN=$a.ci.test" 2>/dev/null
  done
  for a in ML-KEM-512 ML-KEM-768 ML-KEM-1024; do openssl genpkey -algorithm $a -out $a.key; done
  cd ..
else
  echo "OpenSSL $(openssl version | awk '{print $2}') has no ML-DSA/ML-KEM. Re-run generate.sh with OpenSSL 3.5+ to fill this folder." > pqc/README.txt
fi
rm -f "$LEGACY_CNF"
echo "[+] Done -> $(pwd)"
