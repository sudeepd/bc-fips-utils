package org;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.util.encoders.Base64;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;

public class Tests {
    public static void main(String []args) throws Exception{
        Security.addProvider(new BouncyCastleFipsProvider());
        String ENCRYPTION_CERTIFICATE="MIIBkTCB+wIGAVufbLMuMA0GCSqGSIb3DQEBCwUAMA8xDTALBgNVBAMMBHRlc3QwHhcNMTcwNDI0MTAwNDEyWhcNMjcwNDI0MTAwNTUyWjAPMQ0wCwYDVQQDDAR0ZXN0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCrVrCuTtArbgaZzL1hvh0xtL5mc7o0NqPVnYXkLvgcwiC3BjLGw1tGEGoJaXDuSaRllobm53JBhjx33UNv+5z/UMG4kytBWxheNVKnL6GgqlNabMaFfPLPCF8kAgKnsi79NMo+n6KnSY8YeUmec/p2vjO2NjsSAVcWEQMVhJ31LwIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAKKj6Ygftq7iSfvi8G6IoJ4RbknpA0+g+s1fYgmpdHdBEfAfbODmWrNR8GLWQDU0ccnHT0oQDc66ShfluMZ0KAVcfxNJUFP2OYdrGNRJNZbGT9WMcD8LUF8mlACa8uKVfhMU4LssOdEBnW2RpM4xEe1DYPRC+AWoFODb0wsYDwll";
        KeyPair kp = Utils.generateKeyPair();
        String encryptionKey = Base64.toBase64String(kp.getPrivate().getEncoded());
        Certificate oldEncryptionCert = Utils.loadCertificate(ENCRYPTION_CERTIFICATE);
        System.out.println(oldEncryptionCert.toString());
        Certificate newCert = Utils.newCertificateFromExisting(oldEncryptionCert,kp.getPrivate(),kp.getPublic());
        String encryptionCert = Base64.toBase64String(newCert.getEncoded());
        System.out.println(encryptionKey);

        System.out.println(encryptionCert);
    }
}
