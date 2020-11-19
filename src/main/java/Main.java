import org.jmrtd.JMRTDSecurityProvider;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

public class Main {

    public static void main(String[] args) throws Exception {
        String message = "B30D0D9FA0C8BBDF";
        String signature = "46E52F52599A97B7DBBB8BCDD3A3BE6857F4CEF41B0723BE9FBD404DCF471DFC00D2DBF2F5DA6A9B8C1A41893A569873CAD2E90EECEC84DEE85DCDE76041390D1E1328751F2832C83699986744AF68087EFFB21CD9526317424C136911144AE31B00F1764F1C5CCD974D52F6278B029197C5746E62F67C544FA5C9B66E2A8AFB";

        BigInteger modulus = new BigInteger("9cf68418644a5418529373350bafd57ddbf5626527b95e8ea3217d8dac8fbcb7db107eda5e47979b7e4343ed6441950f7fbd921075579104ba081f1a9af950b4c0ee67c2eef2068d9fe2d9d0cfdcbb9be7066e19cc945600e9fd41fc50e771f437ce4bdde63e7acf2a828a4bf38b9f907a252b3dfef550919da1819033f9c619", 16);
        BigInteger pubExp = new BigInteger("10001", 16);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(modulus, pubExp);
        RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);

        Boolean result = verifySignature(publicKey, Utils.hexStringToByteArray(message), Utils.hexStringToByteArray(signature));
        System.out.println("Signature verify result: " + result);
    }

    static Boolean verifySignature(PublicKey pubKey, byte[] origin, byte[] signature) throws Exception {
        if(origin == null || origin.length != 8) {
            throw new Exception("AA failed: bad origin");
        }
        Signature aaSignature = Signature.getInstance("SHA1WithRSA/ISO9796-2", JMRTDSecurityProvider.getBouncyCastleProvider());
        MessageDigest aaDigest = MessageDigest.getInstance("SHA1");
        Cipher aaCipher = Cipher.getInstance("RSA/NONE/NoPadding");
        aaCipher.init(Cipher.DECRYPT_MODE, pubKey);
        aaSignature.initVerify(pubKey);
        int digestLength = aaDigest.getDigestLength(); /* should always be 20 */
        byte[] plaintext = aaCipher.doFinal(signature);
        byte[] m1 = org.jmrtd.Util.recoverMessage(digestLength, plaintext);
        aaSignature.update(m1);
        aaSignature.update(origin);
        return aaSignature.verify(signature);
    }


}
