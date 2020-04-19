import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {
    private BigInteger publicKey;
    private BigInteger privateKey;
    private BigInteger n;

    RSA(){
        // BigInteger constructor generates a random prime
        SecureRandom rand = new SecureRandom();
        BigInteger p = new BigInteger(2048, 100, rand);
        BigInteger q = new BigInteger(2048, 100, rand);

        BigInteger n = p.multiply(q); // n = pq
        // m = (p-1)(q-1)
        BigInteger m = (p.subtract(new BigInteger("1"))).multiply(q.subtract(new BigInteger("1")));
        BigInteger e = new BigInteger("65537");

        BigInteger d = e.modInverse(m);

        this.publicKey = e;
        this.privateKey = d;
        this.n = n;
    }

    RSA(String pubkey, String prikey){
        this.publicKey = new BigInteger(pubkey.split(",")[0]);
        this.n = new BigInteger(pubkey.split(",")[1]);
        this.publicKey = new BigInteger(prikey);
    }

    RSA(String pubkey){
        this.publicKey = new BigInteger(pubkey.split(",")[0]);
        this.n = new BigInteger(pubkey.split(",")[1]);
    }

    byte[] encryptWithPublic(byte[] mes){
        BigInteger enc = new BigInteger(mes).modPow(this.publicKey, this.n);
        return enc.toByteArray();
    }

    byte[] decryptWithPrivate(byte[] mes){
        BigInteger enc = new BigInteger(mes).modPow(this.privateKey, this.n);
        return enc.toByteArray();
    }

    String getPublicKey() {
        return publicKey.toString() + "," + n.toString();
    }
}
