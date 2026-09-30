#!/usr/bin/env python3
"""Scan a folder of crypto material -> inventory.csv + CycloneDX 1.6 CBOM (cbom.json).
Usage: python3 build_inventory.py ./materials"""
import sys, os, csv, json, uuid, hashlib, datetime as dt
from cryptography import x509
from cryptography.hazmat.primitives import serialization as s, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, dsa, x25519, x448, dh
from cryptography.hazmat.primitives.serialization import pkcs12, pkcs7

ROOT = sys.argv[1] if len(sys.argv) > 1 else "./materials"
PASS = b"Test@1234"
NOW = dt.datetime.now(dt.timezone.utc)
rows, comps = [], []

def key_info(k):
    if isinstance(k, (rsa.RSAPrivateKey, rsa.RSAPublicKey)): return "RSA", k.key_size
    if isinstance(k, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)): return f"EC-{k.curve.name}", k.curve.key_size
    if isinstance(k, (dsa.DSAPrivateKey, dsa.DSAPublicKey)): return "DSA", k.key_size
    for t, n, b in [(ed25519.Ed25519PrivateKey,"Ed25519",256),(ed25519.Ed25519PublicKey,"Ed25519",256),
                    (ed448.Ed448PrivateKey,"Ed448",456),(ed448.Ed448PublicKey,"Ed448",456),
                    (x25519.X25519PrivateKey,"X25519",256),(x448.X448PrivateKey,"X448",448)]:
        if isinstance(k, t): return n, b
    if isinstance(k, (dh.DHPrivateKey, dh.DHPublicKey)): return "DH", k.key_size
    return type(k).__name__, None

def risks(alg, bits, sig=None, cert=None):
    r = []
    if alg in ("RSA","DSA","DH") and bits and bits < 2048: r.append(f"{alg}-{bits} too small")
    if sig and any(w in sig.lower() for w in ("md5","sha1")): r.append(f"weak signature {sig}")
    if alg in ("RSA","DSA","DH") or alg.startswith("EC") or alg in ("Ed25519","Ed448","X25519","X448"):
        r.append("quantum-vulnerable")
    if cert is not None:
        if cert.not_valid_after_utc < NOW: r.append("expired")
        elif (cert.not_valid_after_utc - NOW).days <= 30: r.append("expires <=30d")
        if cert.not_valid_before_utc > NOW: r.append("not yet valid")
        if (cert.not_valid_after_utc - cert.not_valid_before_utc).days > 398:
            try:
                if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca: r.append("validity >398d")
            except x509.ExtensionNotFound: r.append("validity >398d")
        try: cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound: r.append("no SAN")
    return r

def add_cert(path, c, container=None):
    k = c.public_key(); alg, bits = key_info(k)
    sig = c.signature_algorithm_oid._name
    fp = c.fingerprint(hashes.SHA256()).hex()
    rows.append(dict(path=path, container=container or "", asset_type="certificate", subject=c.subject.rfc4514_string(),
        issuer=c.issuer.rfc4514_string(), algorithm=alg, key_size=bits, signature_algorithm=sig,
        not_before=c.not_valid_before_utc.isoformat(), not_after=c.not_valid_after_utc.isoformat(),
        sha256_fingerprint=fp, findings="; ".join(risks(alg, bits, sig, c))))
    comps.append({"type":"cryptographic-asset","bom-ref":f"cert:{fp[:16]}","name":c.subject.rfc4514_string(),
        "evidence":{"occurrences":[{"location":path}]},
        "cryptoProperties":{"assetType":"certificate","certificateProperties":{
            "subjectName":c.subject.rfc4514_string(),"issuerName":c.issuer.rfc4514_string(),
            "notValidBefore":c.not_valid_before_utc.isoformat(),"notValidAfter":c.not_valid_after_utc.isoformat(),
            "certificateFormat":"X.509","certificateExtension":os.path.splitext(path)[1].lstrip(".")}}})

def add_key(path, k, kind):
    alg, bits = key_info(k)
    rows.append(dict(path=path, asset_type=kind, algorithm=alg, key_size=bits, findings="; ".join(risks(alg, bits))))
    comps.append({"type":"cryptographic-asset","bom-ref":f"key:{uuid.uuid4().hex[:12]}","name":f"{alg} {kind}",
        "evidence":{"occurrences":[{"location":path}]},
        "cryptoProperties":{"assetType":"related-crypto-material","relatedCryptoMaterialProperties":{
            "type":kind,"size":bits,"format":"PEM/DER"}}})

def try_file(fullpath, path):
    b = open(fullpath,"rb").read(); low = path.lower()
    loaders = [
      ("certs", lambda: x509.load_pem_x509_certificates(b)),
      ("cert",  lambda: [x509.load_der_x509_certificate(b)]),
      ("p7",    lambda: pkcs7.load_pem_pkcs7_certificates(b)),
      ("p7d",   lambda: pkcs7.load_der_pkcs7_certificates(b)),
    ]
    if low.endswith((".pfx",".p12")):
        try:
            k, c, extra = pkcs12.load_key_and_certificates(b, PASS)
            if k: add_key(path, k, "private-key")
            for x in ([c] if c else []) + (extra or []): add_cert(path, x, "PKCS#12")
            return
        except Exception: pass
    if low.endswith(".crl"):
        try: crl = x509.load_pem_x509_crl(b)
        except Exception: crl = x509.load_der_x509_crl(b)
        rows.append(dict(path=path, asset_type="crl", issuer=crl.issuer.rfc4514_string(),
            signature_algorithm=crl.signature_algorithm_oid._name, not_after=crl.next_update_utc.isoformat())); return
    if low.endswith(".csr"):
        r = x509.load_pem_x509_csr(b); alg, bits = key_info(r.public_key())
        rows.append(dict(path=path, asset_type="csr", subject=r.subject.rfc4514_string(), algorithm=alg, key_size=bits)); return
    for name, fn in loaders:
        try:
            for c in fn(): add_cert(path, c, "PKCS#7" if name.startswith("p7") else None)
            return
        except Exception: pass
    for kind, fn in [("private-key", lambda: s.load_pem_private_key(b, None)),
                     ("private-key", lambda: s.load_pem_private_key(b, PASS)),
                     ("private-key", lambda: s.load_der_private_key(b, None)),
                     ("private-key", lambda: s.load_ssh_private_key(b, None)),
                     ("public-key",  lambda: s.load_pem_public_key(b)),
                     ("public-key",  lambda: s.load_ssh_public_key(b.split(b" ")[0]+b" "+b.split(b" ")[1]))]:
        try: add_key(path, fn(), kind); return
        except Exception: pass
    if b"BEGIN DH PARAMETERS" in b:
        p = s.load_pem_parameters(b); bits = p.parameter_numbers().p.bit_length()
        rows.append(dict(path=path, asset_type="dh-parameters", algorithm="DH", key_size=bits,
                         findings="; ".join(risks("DH", bits)))); return
    if b"PGP" in b[:60]:
        rows.append(dict(path=path, asset_type="pgp-key", findings="parse with gpg")); return
    if low.endswith((".jks",".jceks")):
        rows.append(dict(path=path, asset_type="java-keystore", findings="inspect with keytool")); return
    if "symmetric/" in path:
        rows.append(dict(path=path, asset_type="secret-key", algorithm=os.path.basename(path).split(".")[0].upper(),
                         findings="WEAK algorithm" if "WEAK" in path else "")); return

for dp, _, fs in os.walk(ROOT):
    for f in sorted(fs):
        p = os.path.join(dp, f); rp = os.path.relpath(p, ROOT)
        if rp.startswith(("source-code","configs","cbom")) or f=="inventory.csv" or f.endswith((".md",".txt")): continue
        try: try_file(p, rp)
        except Exception as e: rows.append(dict(path=rp, asset_type="unparsed", findings=str(e)[:80]))

fields = ["path","container","asset_type","subject","issuer","algorithm","key_size","signature_algorithm",
          "not_before","not_after","sha256_fingerprint","findings"]
with open(os.path.join(ROOT,"inventory.csv"),"w",newline="") as fh:  # noqa
    w = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n"); w.writeheader()
    for r in rows: w.writerow({k: r.get(k,"") for k in fields})
cbom = {"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":f"urn:uuid:{uuid.uuid4()}","version":1,
        "metadata":{"timestamp":NOW.isoformat(),"component":{"type":"application","name":"CryptoInventory-POC"}},
        "components":comps}
os.makedirs(os.path.join(ROOT,"cbom"), exist_ok=True)
json.dump(cbom, open(os.path.join(ROOT,"cbom","cbom.json"),"w"), indent=2)
print(f"{len(rows)} assets -> inventory.csv, {len(comps)} CBOM components -> cbom/cbom.json")
