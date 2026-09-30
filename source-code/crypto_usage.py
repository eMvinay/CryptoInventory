# TEST FILE - crypto API usage patterns for code scanners (Python)
import hashlib, hmac, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes

HARDCODED_AES_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")   # WEAK: hardcoded key
API_SECRET = "sk_test_CryptoInventoryDummySecret0001"                    # WEAK: hardcoded secret

def weak_hashes(data: bytes):
    return hashlib.md5(data).hexdigest(), hashlib.sha1(data).hexdigest()  # WEAK

def strong_hashes(data: bytes):
    return hashlib.sha256(data).hexdigest(), hashlib.sha3_512(data).hexdigest()

def aes_ecb(data: bytes):                                               # WEAK: ECB mode
    e = Cipher(algorithms.AES(HARDCODED_AES_KEY), modes.ECB()).encryptor()
    return e.update(data.ljust(16, b"\0")) + e.finalize()

def aes_gcm(data: bytes):
    key = AESGCM.generate_key(bit_length=256); nonce = os.urandom(12)
    return AESGCM(key).encrypt(nonce, data, None)

def chacha(data: bytes):
    return ChaCha20Poly1305(ChaCha20Poly1305.generate_key()).encrypt(os.urandom(12), data, None)

def rsa_ops():
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # WEAK: RSA-1024
    k = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ct_bad = k.public_key().encrypt(b"x", padding.PKCS1v15())              # WEAK: PKCS#1 v1.5 enc
    ct_ok = k.public_key().encrypt(b"x", padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
    return weak, ct_bad, ct_ok

def ecdsa_sign(msg: bytes):
    return ec.generate_private_key(ec.SECP384R1()).sign(msg, ec.ECDSA(hashes.SHA384()))

def mac(msg: bytes):
    return hmac.new(API_SECRET.encode(), msg, hashlib.sha256).hexdigest()
