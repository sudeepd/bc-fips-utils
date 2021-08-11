package com.mcafee;

import org.Utils;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Assert;
import org.junit.Test;

import java.io.*;
import java.security.*;
import java.security.spec.*;


import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.KeyManagerFactory;

/**
 * Unit test for simple App.
 */
public class AppTest 
{
    String privateKey1 = "MIICXAIBAAKBgQCrVrCuTtArbgaZzL1hvh0xtL5mc7o0NqPVnYXkLvgcwiC3BjLGw1tGEGoJaXDuSaRllobm53JBhjx33UNv+5z/UMG4kytBWxheNVKnL6GgqlNabMaFfPLPCF8kAgKnsi79NMo+n6KnSY8YeUmec/p2vjO2NjsSAVcWEQMVhJ31LwIDAQABAoGAfmO8gVhyBxdqlxmIuglbz8bcjQbhXJLR2EoS8ngTXmN1bo2L90M0mUKSdc7qF10LgETBzqL8jYlQIbt+e6TH8fcEpKCjUlyq0Mf/vVbfZSNaVycY13nTzo27iPyWQHK5NLuJzn1xvxxrUeXI6A2WFpGEBLbHjwpx5WQG9A+2scECQQDvdn9NE75HPTVPxBqsEd2z10TKkl9CZxu10Qby3iQQmWLEJ9LNmy3acvKrE3gMiYNWb6xHPKiIqOR1as7L24aTAkEAtyvQOlCvr5kAjVqrEKXalj0Tzewjweuxc0pskvArTI2Oo070h65GpoIKLc9jf+UA69cRtquwP93aZKtW06U8dQJAF2Y44ks/mK5+eyDqik3koCI08qaC8HYq2wVl7G2QkJ6sbAaILtcvD92ToOvyGyeE0flvmDZxMYlvaZnaQ0lcSQJBAKZU6umJi3/xeEbkJqMfeLclD27XGEFoPeNrmdx0q10Azp4NfJAY+Z8KRyQCR2BEG+oNitBOZ+YXF9KCpH3cdmECQHEigJhYg+ykOvr1aiZUMFT72HU0jnmQe2FVekuG+LJUt2Tm7GtMjTFoGpf0JwrVuZN39fOYAlo+nTixgeW7X8Y=";
    String privateKey2 = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAtcfyT5pBPGH1q5GXs1YBXh4RUcwoEz+gmCEmDK6MH0ga1PwdXOUBCJn5LMC1Ri0rOes89PQufh5diGi3AdcarIbATQu2PbRyo/E7wEtce+BBnc+olsK+m0fQUjO4mW5SS5AlK539Wrb9Iv7rhwgiAV8/DIlUR+nUItVR4NsGggr/wu82oVs5JfTtmggC1znL9j/wYrSIP0xlu1fKYBPK98H8K/kNJbln+A0sOd/hkAHRnii5UDyttQ1Mj1vnH8L3ghEXCT3wFmbLQgjhYAdVtxCZFU5yRRsw1wojEb2AFIrxHqlfLIWnO0KHo8F0gVhsmo5xXmJ1219zhTJpBXysMQIDAQABAoIBAAGCCJ7lQr9ZVFmRIhvrLbDkgMtA83twunSpwdQI79VTBtAlRzXjSpRqY54j7vYsJurGwtKztPMrkpO/w0uke0t2Ti23uba7QSGtkojIUezbekEDA03VJRgW4cNjeM5fyiLnvO9jrjuU+TBvHiQ6J5RxHqAq0Z1wMwBW7L+0zTymXgMCY5GEoUBQVNAvqdzamchbV4kK6pYOQzdTu0Mw/LK3r1nYlpvMV+7U9rxCeL55QINjM9Mu5eN6kbYpESfWAP1vVEgNwwZzPXfgsHUd9WabTFX0q191l6K3vd2lw7uoaOJdGjltKlZEkezTJVuBtHCxEawQPo55YTecoplsfMUCgYEA/TpsGAsYxehLnoekU54sZrSZMjXa+sqVI0IiW7y9MOy4muvaBSmMwIiAvRG5sf7bG9Ylv7dUI0pRucU6Emm43P63JRFVMHXgidkin0Njc3yiu8e+aduDws/ojgqJTW7Lb44dzOe5jPtt8ydJFM8d26jh2DgZ2oM8XIe3My/d0dUCgYEAt8VR+HA8wywkxGjnRj2PTqmkU73mcmjuSu9tERo1nmoh5TrhXzhJGeQNUx4ven3oiteq/5rBE2E3lb4CmoHGPkX2mpcA97hB/iylojxrcoTQaGuUSMYPCQW28tN6vcwnSIO+AphoxF816Y8Td7wiBs9RSbE2U2t+8L15/Vymwu0CgYEAqg7OAOeS33W9Mt2M8crLrr2iFCIuyTW7Kk6DnHAH7g9Lel7hr43TxIjnTBHXTz4ED5GlEDch/gEvGT7mXO87As7cV7xoJX9EJ872fVZYN3qAHvNpYNXWisHtP1a8FpBNdsFOKgmEhrVjhWPgpGTjfFzSLs6eLizsIIfT9EA1C3ECgYAbFl6qvAB41DznJn9Qfypscdzi6w7YtlbJfNkauD5HB2XPoAowOt+rjU3Zfo2JBJ4OORPfcTQcYywKSmOf2pkZ/L4Is1FVMjen+3S+oSFFVAZUHedRgsAcmFcLG9jvuPPhYGnVgBmROGd98bTw5S4uysg0kIZtbV7cpVEh41JBUQKBgQC4PtlAEmeZwefAl9itHmbi9WQvSPytvDqAH/NwZxG5HComukWns9B8Faxd4pO59uaVsrUr0EM7XauNQ/cJ03S01Hag73p30tO1/jnlGpA3KFFig/8T8GwWKOsQoOW5MstQno43b+ulJO1592JKvy2VXZ80kDUnuJ0v+/weiYkGvQ==\n-----END RSA PRIVATE KEY-----";
    String privateKey3 = "MIICXAIBAAKBgQCrVrCuTtArbgaZzL1hvh0xtL5mc7o0NqPVnYXkLvgcwiC3BjLGw1tGEGoJaXDuSaRllobm53JBhjx33UNv+5z/UMG4kytBWxheNVKnL6GgqlNabMaFfPLPCF8kAgKnsi79NMo+n6KnSY8YeUmec/p2vjO2NjsSAVcWEQMVhJ31LwIDAQABAoGAfmO8gVhyBxdqlxmIuglbz8bcjQbhXJLR2EoS8ngTXmN1bo2L90M0mUKSdc7qF10LgETBzqL8jYlQIbt+e6TH8fcEpKCjUlyq0Mf/vVbfZSNaVycY13nTzo27iPyWQHK5NLuJzn1xvxxrUeXI6A2WFpGEBLbHjwpx5WQG9A+2scECQQDvdn9NE75HPTVPxBqsEd2z10TKkl9CZxu10Qby3iQQmWLEJ9LNmy3acvKrE3gMiYNWb6xHPKiIqOR1as7L24aTAkEAtyvQOlCvr5kAjVqrEKXalj0Tzewjweuxc0pskvArTI2Oo070h65GpoIKLc9jf+UA69cRtquwP93aZKtW06U8dQJAF2Y44ks/mK5+eyDqik3koCI08qaC8HYq2wVl7G2QkJ6sbAaILtcvD92ToOvyGyeE0flvmDZxMYlvaZnaQ0lcSQJBAKZU6umJi3/xeEbkJqMfeLclD27XGEFoPeNrmdx0q10Azp4NfJAY+Z8KRyQCR2BEG+oNitBOZ+YXF9KCpH3cdmECQHEigJhYg+ykOvr1aiZUMFT72HU0jnmQe2FVekuG+LJUt2Tm7GtMjTFoGpf0JwrVuZN39fOYAlo+nTixgeW7X8Y=";

    @Test
    public void verifyHash() throws Exception{
        Security.addProvider(new org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider());
        byte[] salt = new byte[]{18, -126, 107, -16, -60, 89, 8, -24, 26, -68, 19, 15, -115, -22, -116, -122};
        KeySpec spec = new PBEKeySpec("admin".toCharArray(), salt, 27500, 512);

        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256","BCFIPS");
            byte[] key = factory.generateSecret(spec).getEncoded();
            Assert.assertTrue(key.length > 0);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException("Credential could not be encoded", e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }
    public static String removeBeginEnd(String pem) {
        pem = pem.replaceAll("-----BEGIN (.*)-----", "");
        pem = pem.replaceAll("-----END (.*)----", "");
        pem = pem.replaceAll("\r\n", "");
        pem = pem.replaceAll("\n", "");
        return pem.trim();
    }

    public static byte[] pemToDer(String pem) {
        pem = removeBeginEnd(pem);
        return Base64.decode(pem);
    }

    private static String encodeKey(Object obj) {
        try {
            StringWriter writer = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
            pemWriter.writeObject(obj);
            pemWriter.flush();
            pemWriter.close();
            return writer.toString();
        } catch (Exception e) {
            return null;
        }
    }


    @Test
    public void loadPrivateKey() throws Exception{
//        String str = "hello\0\0\0\0";
//        char arr[] = str.toCharArray();
//        Security.addProvider(new org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider());
//        PEMParser parser = new PEMParser(new StringReader(privateKey2));
//        PEMKeyPair pemKeyPair = (PEMKeyPair)parser.readObject();
//
//        PrivateKey pk = new JcaPEMKeyConverter().getPrivateKey(pemKeyPair.getPrivateKeyInfo());

        Security.addProvider(new org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider());
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA","BCFIPS");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        String prKey = Base64.toBase64String(privateKey.getEncoded());
        String puKey = Base64.toBase64String(keyPair.getPublic().getEncoded());

        byte[] der = pemToDer(prKey);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);

        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey pk = kf.generatePrivate(spec);

        Assert.assertNotNull(prKey);
        Assert.assertNotNull(pk);
    }

    @Test
    public void keyTest() throws Exception {
        Security.addProvider(new org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider());
        try {

            String keystorePath = "/Users/sdas/work/keycloak-fips/keycloak/testsuite/integration-arquillian/tests/base/target/containers/auth-server-undertow/client.bcfks";
            String keyPassword = "averylongpassword";
            KeyStore trustStore = KeyStore.getInstance("BCFKS");
            InputStream trustStream = new FileInputStream(new File(keystorePath));
            String defaultKeystoreType = KeyStore.getDefaultType();
            KeyStore keystore = KeyStore.getInstance("BCFKS");

            try (InputStream is = trustStream) {
                trustStore.load(is, keyPassword.toCharArray());
            }

            final KeyManagerFactory kmfactory = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
            kmfactory.init(keystore, keyPassword.toCharArray());
        } catch (NoSuchAlgorithmException var1) {
            throw new Exception(var1.getMessage(), var1);
        }
    }

    @Test
    public void createCertificate(){
        try {
            String cert = Utils.x509CertificateToPem(Utils.getCert());
        }catch(Exception e) {
            Assert.fail();
        }
    }

}
