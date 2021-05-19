import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class HashingPasswords {
    private static final int ITERATIONS = 1000; //As per NIST recomendations https://eprint.iacr.org/2019/161.pdf
    private static final int SALT_SIZE = 16; //16 bits salt as per NIST recomendation
    private static final int HASH_LENGHT = 256; //https://cryptobook.nakov.com/mac-and-key-derivation/pbkdf2
    /*Steps for using PBDKF2:
    * 1.Password should not be empty
    * 2. Instantiate a SecretKeyFactory, java supports:
    *       - AES, ARCFOUR,DES, DESede (3pleDES), PBEWith<digest>And<encryption>,
    *           PBEWith<prf>And<encryption>,PBKDF2WithHmacSHA1.
    * Only the last key derivation function is suitable for password hashing.
    * Currently java doesnt support Argo2, scrypt and bcrypt by default.
    *3. Generate a SecretKey Object
    * 4. Convert the secretKey bytes to a b64 encoded string
    * */
    public static String pbdkf2(char[] password, byte[] salt, int iterations, int keylenght ) throws Exception{
        if (password.length == 0)
            throw new IllegalArgumentException("Password cannot be empty");
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHMACSHA256");
        SecretKey key = skf.generateSecret(
                new PBEKeySpec(password, salt, iterations, keylenght)
        );
        StringBuilder sb = new StringBuilder();
        sb.append(Base64.getEncoder().encodeToString(salt));
        sb.append(":");
        sb.append(ITERATIONS);
        sb.append(":");
        sb.append(Base64.getEncoder().encodeToString(key.getEncoded()));
        return sb.toString();
    }

    public static void main(String args[]){
        //Generate a secure salt
        byte[] salt = new byte[SALT_SIZE];
        SecureRandom secureRandom = new SecureRandom();

        String pass1 = "password123";
        String pass2 = "admin";
        String hash1 = "";
        String hash2 = "";
        try {
            secureRandom.nextBytes(salt);
            hash1 = pbdkf2(pass1.toCharArray(), salt, ITERATIONS, HASH_LENGHT);
            secureRandom.nextBytes(salt);
            hash2 = pbdkf2(pass2.toCharArray(), salt, ITERATIONS, HASH_LENGHT);
        }catch(Exception e){
            e.printStackTrace();
        }
        System.out.println(hash1);
        System.out.println(hash2);
    }
}
