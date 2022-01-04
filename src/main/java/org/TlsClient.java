package org;
import java.security.Security;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
/**
 * Basic SSL Client - using the '!' protocol.
 */
public class TlsClient {
    public static void main(
            String[] args)
            throws Exception {
        Security.addProvider(new BouncyCastleFipsProvider());
        Security.addProvider(new BouncyCastleJsseProvider());
        SSLContext sslContext = SSLContext.getInstance("TLS", "BCJSSE");
        TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance(
                "PKIX", "BCJSSE");
        trustMgrFact.init(Utils.createServerTrustStore());
        sslContext.init(null, trustMgrFact.getTrustManagers(), null);
        SSLSocketFactory fact = sslContext.getSocketFactory();
        SSLSocket cSock = (SSLSocket) fact.createSocket("repo.maven.apache.org", Utils.PORT_NO);
        Protocol.doClientSide(cSock);
    }
}