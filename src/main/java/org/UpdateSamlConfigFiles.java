package org;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.util.encoders.Base64;
import org.model.Mapping;
import org.model.RealmRepresentation;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class UpdateSamlConfigFiles {
    public static void replaceKeys(String srcFile, String destFile, Map<String, Mapping> replacements) throws Exception{
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object>  root = mapper.readValue(new FileInputStream(srcFile),HashMap.class);
        String realmPublicKeyId = Utils.generateJwtKid( Utils.loadRSAPublicKey((String)root.get("publicKey")));
        String newPrivateKey = replacements.get(realmPublicKeyId).getFinalPrivateKey();
        String newPublicKey = replacements.get(realmPublicKeyId).getFinalPublicKey();
        root.put("privateKey",newPrivateKey);
        root.put("publicKey",newPublicKey);
        List clients = (List) root.get("clients");
        for (Object c : clients) {
            Map<String, Object> client = (Map) c;
            HashMap attributes = (HashMap) client.get("attributes");
            String signingCertificateString = (String)attributes.get("saml.signing.certificate");
            String signingPrivateKeyString = (String)attributes.get("saml.signing.private.key");
            String encryptionCertificateString = (String)attributes.get("saml.encryption.certificate");

            if (signingCertificateString != null) {
                Certificate signingCertificate = Utils.loadCertificate(signingCertificateString);
                String signingCertKid = Utils.generateJwtKid(signingCertificate.getPublicKey());
                Mapping mapping = replacements.get(signingCertKid);
                String newSigningPrivateKey, newSigningPublicKey;
                if (mapping != null) {
                    newSigningPrivateKey = mapping.getFinalPrivateKey();
                    newSigningPublicKey = mapping.getFinalPublicKey();
                }else {
                    KeyPair kp = Utils.generateKeyPair();
                    newSigningPrivateKey = Base64.toBase64String(kp.getPrivate().getEncoded());
                    newSigningPublicKey = Base64.toBase64String(kp.getPublic().getEncoded());
                }
                Certificate replacementSigningCertificate = Utils.newCertificateFromExisting(signingCertificate, Utils.loadRSAPrivateKey(newSigningPrivateKey), Utils.loadRSAPublicKey(newSigningPublicKey));
                attributes.put("saml.signing.certificate", Base64.toBase64String(replacementSigningCertificate.getEncoded()));
                if (signingPrivateKeyString != null)
                    attributes.put("saml.signing.private.key",newSigningPrivateKey);
            }

            if (encryptionCertificateString != null) {
                Certificate encryptionCertificate = Utils.loadCertificate(encryptionCertificateString);
                String encryptionCertKid = Utils.generateJwtKid(encryptionCertificate.getPublicKey());
                String newEncryptionPublicKey = replacements.get(encryptionCertKid).getFinalPublicKey();
                String newEncryptionPrivateKey = replacements.get(encryptionCertKid).getFinalPrivateKey();
                Certificate replacementEncryptionCertificate = Utils.newCertificateFromExisting(encryptionCertificate, Utils.loadRSAPrivateKey(newEncryptionPrivateKey), Utils.loadRSAPublicKey(newEncryptionPublicKey));
                attributes.put("saml.encryption.certificate", Base64.toBase64String(replacementEncryptionCertificate.getEncoded()));
            }
        }
        mapper.writerWithDefaultPrettyPrinter().writeValue(new File(destFile),root);
    }

    public static void main(String []args) throws Exception {
        // Load mapping  file
        Security.addProvider(new BouncyCastleFipsProvider());
        Security.addProvider(new BouncyCastleJsseProvider());
        String srcBaseDirectory = "/Users/sdas/work/keycloak-fips/keycloak-upstream";
        String  destBaseDirectory = "/Users/sdas/work/keycloak-fips/kc-saml";
        String samlDirectoryPath = "testsuite/integration-arquillian/tests/base/src/test/resources/adapter-test/keycloak-saml";
        String  mappingFile = Paths.get(destBaseDirectory,"mappings.json").toString();
        String srcSamlBaseDirectory = Paths.get(srcBaseDirectory,samlDirectoryPath).toString();
        String destSamlBaseDirectory = Paths.get(destBaseDirectory,samlDirectoryPath).toString();

        ObjectMapper mapper  = new ObjectMapper();
        TypeReference<HashMap<String, Mapping>> typeRef
                = new TypeReference<>() {};
        HashMap<String, Mapping> mappings = mapper.readValue(new FileInputStream(mappingFile),typeRef);

        String []inputFiles = {
                Paths.get(srcSamlBaseDirectory,"testsaml-behind-lb.json").toString(),
                Paths.get(srcSamlBaseDirectory,"tenant1-realm.json").toString(),
                Paths.get(srcSamlBaseDirectory,"tenant2-realm.json").toString(),
                Paths.get(srcSamlBaseDirectory,"testsaml.json").toString()
        };

        replaceKeys(inputFiles[1], "/tmp/testsaml-behind-lb.json", mappings);

    }
}
