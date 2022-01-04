package org;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.util.encoders.Base64;

import java.net.URL;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.Certificate;

/**
 * Adds a different encryption key to the keystore
 */


public class AddEncryptionKey {
    public static void main(String[] args) {
        try {
            Security.addProvider(new BouncyCastleFipsProvider());
            Security.addProvider(new BouncyCastleJsseProvider());
            String keycloakBaseDirectory = "/Users/sdas/work/keycloak-fips/kc-saml";
            String samlDirectoryPath = "testsuite/integration-arquillian/tests/base/src/test/resources/adapter-test/keycloak-saml";
            String[] inputKeystores = {
                    Paths.get(keycloakBaseDirectory, samlDirectoryPath, "sales-post-enc-sign-assertions-only/WEB-INF/keystore.bcfks").toString(),
                    Paths.get(keycloakBaseDirectory, samlDirectoryPath, "sales-post-enc/WEB-INF/keystore.bcfks").toString(),
                    Paths.get(keycloakBaseDirectory, samlDirectoryPath, "encrypted-post/WEB-INF/keystore.bcfks").toString(),
            };

            String keystorePassword = "averylongpassword";
            String keyPassword = "averylongpassword";
            KeyPair keyPair = Utils.generateKeyPair();
            for (String keystoreFileName : inputKeystores) {
                String alias = Utils.getAliasOfFirstKeyEntry(keystoreFileName, keystorePassword);
                if (alias != null) {
                    String encryptionAlias = new URL(new URL(alias),"encryption").toString();
                    Certificate certificate = Utils.getCertificateFromKeystore(keystoreFileName, keystorePassword, alias);
                    Certificate newCertificate = Utils.newCertificateFromExisting(certificate, keyPair.getPrivate(), keyPair.getPublic());
                    String samlEncryptionCertificate = Base64.toBase64String(newCertificate.getEncoded());
//                    Utils.addKeyToKeystore(keystoreFileName, keystorePassword, encryptionAlias, keyPair.getPrivate(), keyPassword, newCertificate);
                    System.out.println("Encryption Alias = " + encryptionAlias);
                    System.out.println("Encoded certificate = " + samlEncryptionCertificate);
                }
            }
        }catch(Exception ignored) {

        }

    }

}
