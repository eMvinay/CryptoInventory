/* TEST FILE - OpenSSL C API usage patterns */
#include <openssl/evp.h>
#include <openssl/ssl.h>
void demo(void) {
    EVP_MD_fetch(NULL, "MD5", NULL);                              /* WEAK */
    EVP_MD_fetch(NULL, "SHA2-256", NULL);
    EVP_CIPHER_fetch(NULL, "DES-EDE3-CBC", NULL);                 /* WEAK */
    EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    EVP_PKEY *k = EVP_RSA_gen(1024);                              /* WEAK */
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);             /* WEAK */
    SSL_CTX_set_cipher_list(ctx, "RC4-SHA:DES-CBC3-SHA");        /* WEAK */
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384");
}
