import java.security.MessageDigest;
import javax.crypto.Cipher;

public class CryptoExample {

    public static void main(String[] args) throws Exception {
        // Legacy hashing algorithms - not quantum safe.
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");

        // Stronger hashing.
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        // Symmetric encryption.
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
    }
}