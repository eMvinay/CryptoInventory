# CryptoInventory

A repository with the Crypto Inventory materials — **synthetic test data only**. Every key, certificate,
password and secret here was generated for this POC and must never be used in a real system.
Default password for encrypted keys / PFX / keystores: `Test@1234`.

## Layout
| Folder | Contents |
|---|---|
| `certificates/pki-chain` | RSA Root CA → Issuing CA → server (TLS), client-auth, code-signing, S/MIME leaves, fullchain |
| `certificates/ecdsa`, `eddsa` | ECDSA P-256/P-384/P-521, Ed25519, Ed448 certs |
| `certificates/weak` | RSA-1024, SHA-1 & MD5 signed, expired, expiring in 7 days, not-yet-valid, 10-year validity, no SAN, wildcard |
| `certificates/formats` | Same cert as PEM, DER, CER, PKCS#7 (PEM/DER), PKCS#12 (AES-256 and legacy 3DES) |
| `certificates/csr`, `crl` | CSRs (RSA, EC) and a CRL (PEM + DER) |
| `keys/asymmetric` | RSA PKCS#1/PKCS#8/encrypted/DER/public, EC secp256k1 & SEC1, X25519, X448, Ed25519, DSA-1024, DH params |
| `keys/symmetric` | AES-128/256, DES, 3DES, ChaCha20, HMAC secret, an AES-256-CBC encrypted blob |
| `ssh` | OpenSSH RSA-3072, RSA-1024 (weak), ECDSA, Ed25519, authorized_keys, known_hosts |
| `pgp` | RSA-3072 signing + Curve25519 encryption subkey (public & private, armored) |
| `keystores` | JKS, PKCS#12, JCEKS (AES secret key), JKS truststore |
| `pqc` | ML-DSA / SLH-DSA certs and ML-KEM keys (generated only when OpenSSL ≥ 3.5) |
| `source-code` | Crypto API usage (weak + strong) in Python, Java, Go, Node.js, C#, C/OpenSSL |
| `configs` | nginx, Apache, Tomcat, sshd, openssl.cnf, java.security, .env secrets, Kubernetes TLS secret |
| `inventory.csv` | Expected inventory (ground truth) with findings per asset |
| `cbom/cbom.json` | CycloneDX 1.6 CBOM of the file-based assets |

## Regenerate
```bash
./generate.sh ./            # needs openssl, python3 + cryptography; keytool/gpg optional
python3 build_inventory.py ./   # rebuilds inventory.csv and cbom/cbom.json
```
Findings in `inventory.csv` are the "answer key" to compare discovery/CLM tools against.
