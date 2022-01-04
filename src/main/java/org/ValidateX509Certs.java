package org;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.StringReader;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * Used to validate the client certs
 */


public class ValidateX509Certs {
    public static X509Certificate decodeCertificate(String fileName) throws Exception{
        PEMParser parser = new PEMParser(new FileReader(fileName));
        X509CertificateHolder certHolder = (X509CertificateHolder)parser.readObject();
        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }


    public static void main(String[]args) throws Exception{
        byte[] input = {25, 64, -30, 26, 118, -124, 51, 126, -26, -125, -122, 51, -91, 114, 122, -2, 121, -127, -69, 48, -127, -72, -96, 27, 48, 25, -96, 3, 2, 1, 17, -95, 18, 4, 16, -96, -53, 50, -38, 31, -96, -112, 71, -28, -73, 46, -112, -63, 59, -11, -104, -95, 28, 48, 26, 48, 24, -96, 3, 2, 1, 2, -95, 17, 24, 15, 50, 48, 50, 49, 48, 57, 50, 55, 50, 51, 53, 53, 51, 54, 90, -94, 6, 2, 4, 110, -34, -81, 42, -92, 7, 3, 5, 0, 64, 96, 0, 0, -91, 17};
        String str = new String(input);
//        String baseDirectory = "/Users/sdas/work/keycloak-fips/kc-saml";
//        String samlDirectoryPath = "testsuite/integration-arquillian/servers/auth-server/jboss/common/keystore";
//        String cacerts = Paths.get(baseDirectory,samlDirectoryPath,"ca.crt").toString();
//        String clientCert = Paths.get(baseDirectory,samlDirectoryPath,"client.crt").toString();
//        X509Certificate certificate = decodeCertificate(clientCert);
//        String dn = certificate.getSubjectX500Principal().getName();
        System.out.println(str);
    }
}
