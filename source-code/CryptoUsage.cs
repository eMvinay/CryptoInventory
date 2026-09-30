// TEST FILE - .NET crypto usage patterns
using System.Security.Cryptography; using System.Net;
class CryptoUsage {
    const string Key = "MDEyMzQ1Njc4OWFiY2RlZg==";                       // WEAK: hardcoded
    static void Main() {
        MD5.Create(); SHA1.Create();                                      // WEAK
        SHA256.Create();
        TripleDES.Create(); DES.Create();                                 // WEAK
        var aes = Aes.Create(); aes.Mode = CipherMode.ECB;                // WEAK: ECB
        new AesGcm(new byte[32], 16);
        RSA.Create(1024);                                                 // WEAK
        ECDsa.Create(ECCurve.NamedCurves.nistP384);
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;  // WEAK: TLS 1.0
        ServicePointManager.ServerCertificateValidationCallback = (s,c,ch,e) => true; // WEAK
    }
}
