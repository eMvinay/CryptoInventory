// TEST FILE - Java JCA/JCE usage patterns
import javax.crypto.*; import javax.crypto.spec.*; import java.security.*;
public class CryptoUsage {
    private static final String DB_PASSWORD = "P@ssw0rd-CI-Test";              // WEAK: hardcoded
    public static void main(String[] a) throws Exception {
        MessageDigest.getInstance("MD5");                                     // WEAK
        MessageDigest.getInstance("SHA-256");
        Cipher.getInstance("DES/ECB/PKCS5Padding");                           // WEAK
        Cipher.getInstance("DESede/CBC/PKCS5Padding");                        // WEAK (3DES)
        Cipher.getInstance("AES/GCM/NoPadding");
        Cipher.getInstance("RSA/ECB/PKCS1Padding");                           // WEAK padding
        Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA"); rsa.initialize(1024); // WEAK
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC"); ec.initialize(256);
        Signature.getInstance("SHA1withRSA");                                 // WEAK
        Signature.getInstance("SHA384withECDSA");
        Mac.getInstance("HmacSHA256");
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        new SecureRandom(); java.util.Random insecure = new java.util.Random(); // WEAK RNG
        SecretKey k = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");   // WEAK: hardcoded key
    }
}
