package dev.gw;

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


        message = "aad8cc3d08805be9a40b406a7b91f0024b344eb9097aff347dc179055668c69d";
        signature = "0d6f2acf87d0347fb8392fd1e6aa2006cc2ab58a4a5dac928ab57e6a741a676a10a120d71f6fecad067be2fdb3d07178579b9257c943195f7f49dd0e3f66891686971bce2d55b50827148a3b86b5cb20ea507895c7c899e3b010fe8ccae5f1b0dad3c7e0f0dd41414dc50b04a693139251cadc8e8cd6fc1e2111f75bf53ae9f17d8dc9e5e0b9549a53a4238cc4d12c07ad67f8324297809af9517faaca55c6a97e470e60f898094874679a2a8f2ed3f3559e56ddf9e7d86a911f90eb290f1401ae8ed50205df7518df011463ec6660ce6950421c3825f89200c6c39f8c5b4f975dedd75caa24d4807788707b10884a8bed168b05e5f645d59ee7a975f2a7c94944c4934b86c75a4c5662e6e3da82061b7aa09cc4c7b099dec76f84b12e4a160740f7e843f888b7fcfd56425b8c3da52ddbbbc491078935e241c148b724a0b00380d8be2fbfbe575fdbcef7641671021d07eebb9ac90be4105caadaa9c0bb899a30687bb9ea7fd3062aff58e06fdf750f589c74fd4115cf32bc19304e57d9c44865e5c38d9dda14c52b867a5d3b278d7a7df2b5444c97f3e2dedf36a4eab6d1c10e86a78220b8067ea883340a0204ee4e2aee465e972ded4591090812c704a0877b5888c567dea759b26406fb29210e1ecda1ca2a4fc2b0a7811764e70d17419ae0cda39312daedd252e6de4690d800edaee60d0d0445ead352b9089a039036da";
        for (int i = 0; i < 4; i++) {
            String subMessage = message.substring(16 * i, 16 * (i + 1));
            String subSignature = signature.substring(256 * i, 256 * (i + 1));
            result = verifySignature(publicKey, Utils.hexStringToByteArray(subMessage), Utils.hexStringToByteArray(subSignature));
            System.out.println("Multi signature verify result: " + result);
        }
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
