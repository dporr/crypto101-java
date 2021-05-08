import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.Security;
import java.util.Arrays;
import java.util.stream.Stream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

public class Crypto101 {
    /**
     * List all the security providers available
     * Security provider implements some or all parts of Java Security.
     * Services that a provider may implement include:
     * Algorithms (such as DSA, RSA, MD5 or SHA-1).
     * Key generation, conversion, and management facilities (such as for algorithm-specific keys).
    * */
    public void getProviders(){
        Arrays.stream(Security.getProviders()).forEach(System.out::println);
    }
public static void main(String... args){
    Crypto101 crypto101 = new Crypto101();
    crypto101.getProviders();
}
}
