package org;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;

import javax.security.auth.x500.X500Principal;
import javax.security.auth.x500.X500PrivateCredential;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.util.Enumeration;

/**
 * Certificate/Key Utilities for the examples.
 */
public class Utils
{
    /**
     * Host name for our examples to use.
     */
    static final String HOST = "localhost";

    /**
     * Port number for our examples to use.
     */
    static final int PORT_NO = 9020;
    /**
     * Algorithm for signing certificates
     */
    private static final String SIGNATURE_ALGORITHM = "SHA256WithRSA";
    /**
     * Names and passwords for the key store entries we need.
     */
    public static String ROOT_ALIAS = "root";
    public static final char[] SERVER_PASSWORD = "serverPassword".toCharArray();
    private static long baseTime = 0x15c57a33402L;

    private static final byte[]rootPrivateKey = Base64.decode("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDBGYuO7kuxJgLBj2SuyJ1QwSaaPVTfIq+v03i7YJVa6e5EekdhFS16YE8CZKhf+LQjn4fJcDNWEZuynRlpYaCXlav9wRO31P6YCyL7RiAxJTuDyO/Umy0uRPs1WQ69WDVoxwzOb6mXvpjfME2El6aPxbIZxNiRdlzcXc4cGtbTdvAG+B04HaZyOKl+TtB3c86cSHOw4xz+SeuuR2CdktwA9cTAHEL5RAf2LWwf9R3JsH5tAvHScxBIVL6URAjTrAxzCkg/h6ZYInGzRoaiL5z8OQhm9XJz6dTlGWo4atuZweey79b5YSTjVOjJ0APIfrce/fEkuHuKy4/0iukFeoT5AgMBAAECggEAEAyWe9e0dNHK8tl/LcPAx4B2O+WTE0Snw35ZD4HUiAzfX9Ol8Ry4fe5ZQsKo9+kM19UfjQ+FRMcL4MmL3iVeGps3A00z3ViXnH14d9f5PvxwOODPhiUrmSfklSeEwRn+vmmk19eSCemufQZfuwB7uIFe7yNcOKLUzwAA7HcSmdqopbln3sLVshjCUHOZIzesiigvOGx4w820BBiCE6HcIdO7RDD7ChfjpuRBR2tFGIzTeAlyQ/eRrdZnVryLr006QMGQuTxc5MXlnHqjmIH2Vb7XWmR3zSFe8EraIJeIu4fYtv/uVov/CuIOwdGkx0H4pgnyyypWBTnjgzqGQLhRMQKBgQD3tXN6rTQcRR8/PJJsptVhADAdiTcp9GTBHWYZlg3ZWAJI7IkDuqS+sgXzkwlP2k+HSTS7X9S9dx2or+VSXNLEb5JiGXmpJeSdlGZQ4SW0vwfbw+d/1TauGWE+sLltTKXVN84xysAJgQWrEpqKj0zhIs3TCzlnYz3Vh5yFy+RUPQKBgQDHkCoWkt5tOnjxghSsD17ZztG6L5T1VCFtOBNSlZk7EpwcAB4112rND1UZKL3o66to7ecDe2o4DlssBY5lcj893NghDAN0kM/ho3JG/ty/yYVYAWN5wlEECGd0Qzt/K6qnVPxEA5wxAkmGMWLAekCM/wbcY/uRkRG2PLWLQYyzbQKBgQDh8Q5OPaIkjx/7TEK6/EnxWnyI1FoO2K72PtycRfSH5PDgl3A6iIowrq0jCWEbByQ3YBzLNJQV5YqWDSr9P1G4f5RkCpygHsIyweO5rkP4Y67FVCHaxh5EGz5KMmRQP/ObUnWvkSItCRSkgCmabS9Qw7A96iUIGsuR80pf+CRieQKBgFhMFCM6xoljtsF8wbLDdj8+wBL2HJ1TpRqTFhGTOWImwMWu068U6h9i6k8gdK6LH6Nkp7MltwCocXSP3MpL+2levo4Yp6q6rA/05oo9F+UPwB0JOD9WV8xF/6g0Wy3QX0h8VMWvJzuT/H4QedYaAVehOyLmZhepLUIJqHW+AggdAoGAcSWOD6I7RywCP9fLzPFO5wkaT5TfvyKukDCqt3sykWoIG5nQ1fvIQkF60BKMrnCpYdXIHidR0ulusr82eZF/PuAwjO9wM8UqWmOCWxQJtJPxBH4EQgC3oXZgorFcydtZ7XPqkBPJFa0bzLsPgRXeLVic2LwFFsqwTL6KuU+G7oM=");
    private static final byte[]rootPublicKey = Base64.decode("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwRmLju5LsSYCwY9krsidUMEmmj1U3yKvr9N4u2CVWunuRHpHYRUtemBPAmSoX/i0I5+HyXAzVhGbsp0ZaWGgl5Wr/cETt9T+mAsi+0YgMSU7g8jv1JstLkT7NVkOvVg1aMcMzm+pl76Y3zBNhJemj8WyGcTYkXZc3F3OHBrW03bwBvgdOB2mcjipfk7Qd3POnEhzsOMc/knrrkdgnZLcAPXEwBxC+UQH9i1sH/UdybB+bQLx0nMQSFS+lEQI06wMcwpIP4emWCJxs0aGoi+c/DkIZvVyc+nU5RlqOGrbmcHnsu/W+WEk41ToydADyH63Hv3xJLh7isuP9IrpBXqE+QIDAQAB");

    //    private static final byte[] rootPrivateKey = Base64.decode(
//            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD" +
//                    "DYu2zJUsZAKQ31RzVqteZQwf4lxi3T8TCP8DSQ7Ke4IQp3DDKVP" +
//                    "9NUwVHRr/s0OZphln6JyUBkSHuQ2hTx4UQRoef2g06WLlFAHi1R" +
//                    "wr0QefkdGwhPgSuXMWh4dZ1AYGwuIK3KUIUfUU7x5aiwSO6Lyj5" +
//                    "BYTQQqeX4VFMmp1SMMU7tI88R5bAOkiJw1Wz/840BfVowPTR4Wt" +
//                    "TGgq33OJ8gb6GH8k1t8CdvmuFArV5D+iPApiluwVVCVINkSN0Aj" +
//                    "XwmkjtHUMOA+qC7aeZkzke4vPSSy1QABIzmAXIq1zUxS6o9DUqE" +
//                    "H9gLF1e91uqwKjmjj9SYnhZxHumEEx42J/XAgMBAAECggEAWdQZ" +
//                    "SYQrTx7q4RpzK87kWXumZgV9oQWlBdOOwHzMWdwKFz67FcLXL4M" +
//                    "sSZU+9s8iJ8DTjD1D98D0cxj9lYsE47Mxdm4nJ7yTzSQG2v0DDc" +
//                    "JhLTjTX8MmHs3bNO5iDSA4snlZ64Cl90qSsoWz/TbDyL0W3spJQ" +
//                    "gBrEdpO6OOq0ZZ54zekawgyG677aJbzInAG2o9b066HvGRSWNb3" +
//                    "Celw7RKvjPOohKPOWbSm2W/5gnlSnTaAUgm7W8A1AClTt7scyqg" +
//                    "PEtThxQHiBGorI6UGjVuO0xoT1MgYr2QWKaYJydo8mFaygaJxVJ" +
//                    "Hs1PeFQIhuJn7rA/F5BO8cFpuZGrYPUQKBgQDjJYQ7pDrrgRF8O" +
//                    "TDkvbR5lQdBEWHlK8MMD+1kyptwc8UpK2phZjqLOMofsLhURkgm" +
//                    "Fzc0UOEx03MdGJvHrWgGQRBc+0JHvYLzCepbOFumjkSPwbb2yQH" +
//                    "R9QfOPbDRpaqdFNTJnm4lQHZdTGTR4UvDX1X0PuCksRAVtPRA6P" +
//                    "sBsQKBgQDcNJ5H/ZwkSpT8ZA9GzdVJtxoCLjQPyi1AYYZp0xDUo" +
//                    "D0h6+JnDljFnsWnpy9OcoJAA6pCkQe+6Cm0vlLvMQ8eD9rcQ/+s" +
//                    "JFacr7lE3K9bYt56PBTLHyE+WYy90mOVu7FtLfOLz9XDjzyGMn2" +
//                    "ELuFrUjxlnI7ZCbpZh/GwXiXUBwKBgQDPTPbwg4KuWb2+dGd16t" +
//                    "ghuevD63w/bX/1qzeJrArORynh19ifiW/WjX6SC3M+nmHMOZXNL" +
//                    "h9HnOXK4SGSy2RLiOfJJBoqZP90lVEH7VhfmiliVXWIpov9tLVp" +
//                    "+Q09WAdsko1ccDWv07Pyk/zTOt0tMf29CgF07I90cBAWiUpDEQK" +
//                    "BgBycTZBm+BmTAyaDzaRSbArm2l88J5GBoD2ELlWjkcU+iJLWth" +
//                    "TTvV730RCGXVQg9qFgmIeLlmkMexa7v8TKJ/+s6a/Cuf5gvkwfX" +
//                    "MAAuFv0TZmuIrl9cvFJ60pigoPa3iOkW8dnmouNGb0J5Fr/SFSM" +
//                    "W8KMA9dZNzgYvKNAqEOTAoGBALIUD1PsOGciRA8htw3jA8hhaH8" +
//                    "rM+UeQEMC87QnsMEYTuXmkvsDHDNpkcs//X3woQBww+ll1qfByP" +
//                    "Wj4/GNn4vPjwah4M+6c2xFUez3hLpexD0qoeOS3udAXDGfvBiAT" +
//                    "zXkaQ1kp2LHPuQdBMGRM4vnbDYGjtq40khezAfHErK0");
//    private static final byte[] rootPublicKey = Base64.decode(
//            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw2LtsyV" +
//                    "LGQCkN9Uc1arXmUMH+JcYt0/Ewj/A0kOynuCEKdwwylT/TVMFR0" +
//                    "a/7NDmaYZZ+iclAZEh7kNoU8eFEEaHn9oNOli5RQB4tUcK9EHn5" +
//                    "HRsIT4ErlzFoeHWdQGBsLiCtylCFH1FO8eWosEjui8o+QWE0EKn" +
//                    "l+FRTJqdUjDFO7SPPEeWwDpIicNVs//ONAX1aMD00eFrUxoKt9z" +
//                    "ifIG+hh/JNbfAnb5rhQK1eQ/ojwKYpbsFVQlSDZEjdAI18JpI7R" +
//                    "1DDgPqgu2nmZM5HuLz0kstUAASM5gFyKtc1MUuqPQ1KhB/YCxdX" +
//                    "vdbqsCo5o4/UmJ4WcR7phBMeNif1wIDAQAB");
    // 10 years
    private static final long VALIDITY_PERIOD = 3650 * 24 * 60 * 60 * 1000L;
    /**
     * Create a fixed 2048 bit RSA key pair – to keep the server cert stable
     */
    public static KeyPair generateRootKeyPair(String keystoreFile, String storePassword, String keyPassword, String keyAlias) throws Exception {
        InputStream stream = new FileInputStream(keystoreFile);
        try {
            KeyStore keyStore = KeyStore.getInstance("BCFKS");

            keyStore.load(stream, storePassword.toCharArray());
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, keyPassword.toCharArray());
            if (privateKey == null) {
                throw new RuntimeException("Couldn't load key with alias '" + keyAlias + "' from keystore");
            }
            PublicKey publicKey = keyStore.getCertificate(keyAlias).getPublicKey();
            return new KeyPair(publicKey, privateKey);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load private key: " + e.getMessage(), e);
        }
    }

    public static String encodeBase64ToBase64Url(String base64) {
        String s = base64.split("=")[0]; // Remove any trailing '='s
        s = s.replace('+', '-'); // 62nd char of encoding
        s = s.replace('/', '_'); // 63rd char of encoding
        return s;
    }

    public static String encode(byte[] bytes) {
        String s = Base64.toBase64String(bytes);
        return encodeBase64ToBase64Url(s);

    }


    public static KeyPair generateRootKeyPair()
            throws Exception
    {
        KeyFactory kFact = KeyFactory.getInstance("RSA", "BCFIPS");
        return new KeyPair(
                kFact.generatePublic(new X509EncodedKeySpec(rootPublicKey)),
                kFact.generatePrivate(new PKCS8EncodedKeySpec(rootPrivateKey)));
    }
    /**
     * Generate a sample V1 certificate to use as a CA root certificate
     */
    public static X509CertificateHolder generateRootCert(KeyPair pair)
            throws Exception
    {
        JcaX509v1CertificateBuilder certBldr = new JcaX509v1CertificateBuilder(
                new X500Principal("CN=Test CA Certificate"),
                BigInteger.valueOf(1),
                new Date(baseTime), // allow 1024 weeks for the root
                new Date(baseTime + 1024 * VALIDITY_PERIOD),
                new X500Principal("CN=Test CA Certificate"),
                pair.getPublic()
        );
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BCFIPS").build(pair.getPrivate());
        System.out.println("Kid is " + encode(MessageDigest.getInstance("SHA-256").digest(pair.getPublic().getEncoded())));
        return certBldr.build(signer);
    }
    /**
     * Generate a X500PrivateCredential for the root entity.
     */
    public static X500PrivateCredential createRootCredential()
            throws Exception
    {
        KeyPair rootPair = generateRootKeyPair();
        X509Certificate rootCert = convertCert(generateRootCert(rootPair));
        return new X500PrivateCredential(
                rootCert, rootPair.getPrivate(), ROOT_ALIAS);
    }

    private static X509Certificate convertCert(X509CertificateHolder certHolder)
            throws CertificateException
    {
        return new JcaX509CertificateConverter()
                .setProvider("BCFIPS").getCertificate(certHolder);
    }
    /**
     * Create a server trust store.
     *
     * @return a key store containing the example server certificate
     */
    public static KeyStore createServerTrustStore()
            throws Exception
    {
        X500PrivateCredential serverCred = createRootCredential();
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);
        keyStore.setCertificateEntry(
                serverCred.getAlias(), serverCred.getCertificate());
        return keyStore;
    }
    /**
     * Create a server key store.
     *
     * @return a key store containing the example server
     * certificate and private key
     */
    public static KeyStore createServerKeyStore()
            throws Exception
    {
        X500PrivateCredential serverCred = createRootCredential();
        KeyStore keyStore = KeyStore.getInstance("BCFKS");
        keyStore.load(null, null);
        keyStore.setKeyEntry(
                serverCred.getAlias(), serverCred.getPrivateKey(), SERVER_PASSWORD,
                new X509Certificate[] { serverCred.getCertificate() });
        return keyStore;
    }

    public static X509Certificate getCert() throws Exception{
        return convertCert(generateRootCert(generateRootKeyPair()));
    }


    public static X509Certificate getCert(String keystoreFile, String storePassword, String keyPassword, String keyAlias) throws Exception{
        return convertCert(generateRootCert(generateRootKeyPair(keystoreFile, storePassword, keyPassword, keyAlias)));
    }


    public static String x509CertificateToPem(final X509Certificate cert) throws IOException {
        final StringWriter writer = new StringWriter();
        final JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
        pemWriter.writeObject(cert);
        pemWriter.flush();
        pemWriter.close();
        return writer.toString();
    }


    public static void copyTruststoreAlongsideKeystore(String current, String keystoreFileName, String trustStoreFilePath) throws Exception {
        File file = new File(current);
        Path originalPath = Paths.get(trustStoreFilePath);
        if (file.isFile() && file.getName().equals(keystoreFileName)) {
            // Parent directory contains keystore
            String parent = file.getParent();
            Path copied = Paths.get( parent , originalPath.getFileName().toString());

            Files.copy(originalPath, copied, StandardCopyOption.REPLACE_EXISTING);
        }

        if (file.isDirectory()){
            File[] filesList = file.listFiles();
            if (filesList == null) filesList = new File[0];
            for (File f : filesList)
                copyTruststoreAlongsideKeystore(f.getAbsolutePath(),keystoreFileName, trustStoreFilePath);
        }

    }

    public static void replaceBCFKSPrivateKeys(
            String current,
            String keystoreFileName,
            String keyStorePassword,
            PrivateKey privateKey,
            PublicKey publicKey,
            String newKeyPassword) throws Exception {
        File file = new File(current);

        if (file.isFile() && file.getName().equals(keystoreFileName)) {
            KeyStore keyStore = KeyStore.getInstance("BCFKS", "BCFIPS");

            boolean ok = true;
            try (FileInputStream storeStream = new FileInputStream(file)) {
                keyStore.load(storeStream, keyStorePassword.toCharArray());
                Enumeration<String> aliases = keyStore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    if (keyStore.isKeyEntry(alias)) {
                        Certificate certificate = keyStore.getCertificate(alias);
                        Certificate newCert = newCertificateFromExisting(certificate, privateKey, publicKey);
                        keyStore.deleteEntry(alias);
                        keyStore.setCertificateEntry(alias, newCert);
                        keyStore.setKeyEntry(alias, privateKey, newKeyPassword.toCharArray(), new Certificate[]{newCert});
                    }
                }
            } catch (Exception e) {
                System.out.println("Could not update keystore at " + file.getAbsolutePath());
                ok = false;
            }

            if (ok) {
                File outputFile = new File(file.getParent() + "/keystore.new.bcfks");
                try (FileOutputStream storeStream = new FileOutputStream(outputFile)) {
                    keyStore.store(storeStream, keyStorePassword.toCharArray());
                    System.out.println("Wrote keystore to " + outputFile.getAbsolutePath());
                }
            }
        }

        if (file.isDirectory()) {
            File[] filesList = file.listFiles();
            if (filesList == null) filesList = new File[0];
            for (File f : filesList) {
                if (f != null) {
                    replaceBCFKSPrivateKeys(f.getAbsolutePath(), keystoreFileName, keyStorePassword, privateKey, publicKey, newKeyPassword);
                }
            }
        }
    }

    public static Certificate newCertificateFromExisting(Certificate certificate, PrivateKey privateKey, PublicKey publicKey) throws OperatorCreationException, CertificateException, IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        SecureRandom random = new SecureRandom();

        X509CertificateHolder oldCert = new X509CertificateHolder(certificate.getEncoded());
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                oldCert.getIssuer(),
                oldCert.getSerialNumber(),
                oldCert.getNotBefore(),
                oldCert.getNotAfter(),
                oldCert.getSubject(),
                publicKey
        );

        BasicConstraints constraints = new BasicConstraints(true);
        builder.addExtension(
                Extension.basicConstraints,
                true,
                constraints.getEncoded());
        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .build(privateKey);
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter()
                .getCertificate(holder);
    }


    public static void changeAllPrivateKeysInBcfksFiles(
            String current,
            String keystoreFileName,
            String keyStorePassword,
            String oldKeyPassword,
            String newKeyPassword) throws Exception {
        File file = new File(current);
        if (file.isFile() && file.getName().equals(keystoreFileName)) {
            boolean hasError = false;
            KeyStore ks = KeyStore.getInstance("BCFKS","BCFIPS");
            try {
                ks.load(new FileInputStream(file), keyStorePassword.toCharArray());
                Enumeration<String> aliases = ks.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    if (ks.isKeyEntry(alias)) {
                        try {
                            Key key = ks.getKey(alias, oldKeyPassword.toCharArray());
                            Certificate cert = ks.getCertificate(alias);
                            ks.deleteEntry(alias);
                            ks.setKeyEntry(alias, key, newKeyPassword.toCharArray(), new Certificate[]{cert});
                            key = ks.getKey(alias, newKeyPassword.toCharArray());
                            System.out.println("Key " + alias + " at " + file.getAbsolutePath() + " has algo " + key.getAlgorithm());
                        } catch (Exception e) {
                            hasError = true;
                            System.out.println("Unable to load key " + alias);
                        }
                    }
                }
                if (!hasError) {
                    file.renameTo(new File(current + ".bkp"));
                    ks.store(new FileOutputStream(current), keyStorePassword.toCharArray());
                }
            }catch (Exception e) {
                System.out.println("Unable to load key store at " + current);
            }
        }

        if (file.isDirectory()){
            File[] filesList = file.listFiles();
            if (filesList == null) filesList = new File[0];
            for (File f : filesList)
                changeAllPrivateKeysInBcfksFiles(f.getAbsolutePath(),keystoreFileName,keyStorePassword, oldKeyPassword,newKeyPassword);
        }
    }

    public static KeyPair createKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(3072);
        return keyPairGenerator.generateKeyPair();
    }

    public static PrivateKey loadRSAPrivateKey(String privateKey) {
        byte[] keyBytes = Base64.decode(privateKey);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load key in PKCS8 format", e);
        }
    }

    public static PublicKey loadRSAPublicKey(String publicKey) {
        byte[] keyBytes = Base64.decode(publicKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        try {
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to key", e);
        }
    }
}