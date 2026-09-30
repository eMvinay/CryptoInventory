// TEST FILE - Go crypto usage patterns
package main
import ("crypto/aes"; "crypto/cipher"; "crypto/des"; "crypto/ecdsa"; "crypto/ed25519"; "crypto/elliptic"
        "crypto/md5"; "crypto/rand"; "crypto/rc4"; "crypto/rsa"; "crypto/sha256"; "crypto/tls")
func main() {
    md5.Sum([]byte("x"))                                   // WEAK
    sha256.Sum256([]byte("x"))
    des.NewCipher([]byte("8bytekey"))                      // WEAK
    rc4.NewCipher([]byte("rc4-key"))                       // WEAK
    b, _ := aes.NewCipher(make([]byte, 32)); cipher.NewGCM(b)
    rsa.GenerateKey(rand.Reader, 2048)
    ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    ed25519.GenerateKey(rand.Reader)
    _ = &tls.Config{MinVersion: tls.VersionTLS10, InsecureSkipVerify: true} // WEAK
    _ = &tls.Config{MinVersion: tls.VersionTLS13}
}
