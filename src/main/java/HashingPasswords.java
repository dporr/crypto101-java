import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import java.util.Base64;

public class HashingPasswords {
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
    public String pbdkf2(char[] password, byte[] salt, int iterations, int keylenght ) throws Exception{
        if (password.length == 0)
            throw new IllegalArgumentException("Password cannot be empty");
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHMACSHA256");
        SecretKey key = skf.generateSecret(
                new PBEKeySpec(password, salt, iterations, keylenght)
        );
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }
}
