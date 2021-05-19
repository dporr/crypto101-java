import java.security.Provider;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.Security;
import java.security.Provider.Service;
import java.util.ArrayList;
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
    /**
     * Each security provider has Services that are the actual implementations of algorithms
     * **/
    public void getServices(){
        ArrayList arrayList = new ArrayList();

        Arrays.stream(Security.getProviders()).
            map(Provider::getServices).forEach(arrayList::add);
        System.out.println(arrayList);
    }
public static void main(String... args){
    Crypto101 crypto101 = new Crypto101();
    crypto101.getServices();
}
}
