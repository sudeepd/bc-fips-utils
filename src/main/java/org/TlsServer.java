package org;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.net.ssl.*;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.util.encoders.Base64;

/**
 * Basic SSL Server - using the '!' protocol.
 */
public class TlsServer
{
    private static final TrustManager TRUST_ALL_MANAGER = new X509TrustManager() {
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }

        public void checkClientTrusted(X509Certificate[] certs, String authType) {

        }

        public void checkServerTrusted(X509Certificate[] certs, String authType) {
        }
    };


    public static SSLContext initializeTLS() {
        try {
            String keystorePath = Paths.get(TlsServer.class.getResource("/keycloak.bcfks").toURI()).toAbsolutePath().toString();
            KeyStore keystore = KeyStore.getInstance("bcfks");

            try (FileInputStream is = new FileInputStream(keystorePath)) {
                keystore.load(is, "averylongpassword".toCharArray());
            }
            System.out.println("Loaded keystore successfully");

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            System.out.println("Initializing key manager factory");
            keyManagerFactory.init(keystore, "averylongpassword".toCharArray());
            System.out.println("Done key manager factory");
            KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

            String truststorePath = Paths.get(TlsServer.class.getResource("/keycloak.truststore.bcfks").toURI()).toAbsolutePath().toString();

            // Essentially, this is REQUEST CLIENT AUTH behavior. It doesn't fail if the client doesn't have a cert.
            // However it will challenge him to send it.
            KeyStore truststore = KeyStore.getInstance("bcfks");
            System.out.println("Loading trust store");

            try (FileInputStream is = new FileInputStream(truststorePath)) {
                truststore.load(is, "averylongpassword".toCharArray());
            }
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            System.out.println("Initializing trust manager factory");
            trustManagerFactory.init(truststore);
            TrustManager[] trustManagers = new TrustManager[trustManagerFactory.getTrustManagers().length + 1];
            for (int i = 0; i < trustManagerFactory.getTrustManagers().length; ++i) {
                trustManagers[i] = trustManagerFactory.getTrustManagers()[i];
            }
            trustManagers[trustManagers.length - 1] = TRUST_ALL_MANAGER;

            SSLContext sslContext;
            sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagers, trustManagers, null);
            return sslContext;
        } catch (Exception e) {
            System.out.println("Exception " + e.getMessage());
            throw new IllegalStateException("Could not initialize TLS", e);
        }
    }


    public static void main(
            String[] args)
            throws Exception
    {
        Security.addProvider(new BouncyCastleFipsProvider());
        Security.addProvider(new BouncyCastleJsseProvider());
        X509Certificate cert = Utils.getCert("/tmp/keystore.bcfks","averylongpassword","averylongpassword","secure-portal");
        String base64Cert = Base64.toBase64String(cert.getEncoded());
        for (Provider provider : Security.getProviders()) {
            System.out.println(provider.getName() + ": " + provider.getInfo());
        }

//        Utils.copyTruststoreAlongsideKeystore();

//        Utils.changeAllPrivateKeysInBcfksFiles("/Users/sdas/work/keycloak-fips/keycloak/testsuite/integration-arquillian/tests/base/src/test/resources/adapter-test/keycloak-saml",
//                "keystore.bcfks",
//                "averylongpassword",
//                "test123",
//                "averylongpassword");

        //        SSLContext sslContext = initializeTLS();
        SSLContext sslContext = SSLContext.getInstance("TLS", "BCJSSE");
//        KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance(
                "PKIX", "BCJSSE");
        keyMgrFact.init(Utils.createServerKeyStore(), Utils.SERVER_PASSWORD);

        sslContext.init(keyMgrFact.getKeyManagers(), null, null);
        SSLServerSocketFactory fact = sslContext.getServerSocketFactory();
        SSLServerSocket sSock = (SSLServerSocket)fact.createServerSocket(
                Utils.PORT_NO);
        while(true) {
            try {
                SSLSocket sslSock = (SSLSocket)sSock.accept();
                Protocol.doServerSide(sslSock);
            }catch(Exception e) {
                System.out.println(e);
            }
        }
    }
}