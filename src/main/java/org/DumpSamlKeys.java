package org;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.model.KeystorePojo;
import org.model.Mapping;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Go over the directory, and dump all saml data that you can find
 */
public class DumpSamlKeys {
    private static final String KeyStoreFileName = "keystore.jks";
    private static final String KeyStorePasssword = "store123";
    private static final String KeyPassword = "test123";

    private static final String DestKeyStoreFileName = "keystore.bcfks";
    private static final String DestKeyStorePasssword = "averylongpassword";
    private static final String DestKeyPassword = "averylongpassword";

    private static List<KeystorePojo> transformSamlKeys( List<KeystorePojo> ksp, Map<String ,KeyPair> replacementKeys) {
        return ksp.stream().map( k -> {
            try {
                KeystorePojo pojo = new KeystorePojo();
                KeyPair newSpKeyPair = replacementKeys.get(k.getSpPublicKeyId());
                KeyPair newIdpKeyPair = replacementKeys.get(k.getIdpPublicKeyId());
                Certificate spCertificate = Utils.loadCertificate(k.getSpCertificate());
                Certificate idpCertificate = Utils.loadCertificate(k.getIdpCertificate());
                Certificate replacementSpCertificate = Utils.newCertificateFromExisting(spCertificate,newSpKeyPair.getPrivate(), newSpKeyPair.getPublic());
                Certificate replacementIdpCertificate = Utils.newCertificateFromExisting(idpCertificate,newIdpKeyPair.getPrivate(),newIdpKeyPair.getPublic());

                pojo.setFileName(k.getFileName());
                pojo.setSpKeyAlias(k.getSpKeyAlias());
                pojo.setSpPrivateKey(Base64.toBase64String(newSpKeyPair.getPrivate().getEncoded()));
                pojo.setSpPublicKeyId(Utils.generateJwtKid(newSpKeyPair.getPublic()));
                pojo.setSpCertificate(Base64.toBase64String(replacementSpCertificate.getEncoded()));

                pojo.setIdpCertificateAlias(k.getIdpCertificateAlias());
                pojo.setIdpCertificate(Base64.toBase64String(replacementIdpCertificate.getEncoded()));
                pojo.setIdpPublicKeyId(Utils.generateJwtKid(newIdpKeyPair.getPublic()));
                pojo.setIdpPrivateKey(Base64.toBase64String(newIdpKeyPair.getPrivate().getEncoded()));
                return pojo;
            } catch(Exception c) {
                return  null;
            }
        }).filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    private static List<KeystorePojo> transformOutputPaths(List<KeystorePojo> ksp,String srcDirectory , String destinationDirectory) {
        return ksp.stream().map( k -> {
            KeystorePojo pojo = new KeystorePojo();
            pojo.setIdpPublicKeyId(k.getIdpPublicKeyId());

            pojo.setSpKeyAlias(k.getSpKeyAlias());
            pojo.setSpPublicKeyId(k.getSpPublicKeyId());
            pojo.setSpCertificate(k.getSpCertificate());
            pojo.setSpPrivateKey(k.getSpPrivateKey());

            pojo.setIdpCertificateAlias(k.getIdpCertificateAlias());
            pojo.setIdpCertificate(k.getIdpCertificate());
            pojo.setIdpPublicKeyId(k.getIdpPublicKeyId());
            pojo.setIdpPrivateKey(k.getIdpPrivateKey());

            String fileName = k.getFileName();
            String destination = fileName.replace(srcDirectory,destinationDirectory);
            destination = destination.replace(KeyStoreFileName, DestKeyStoreFileName);
            pojo.setFileName(destination);
            return pojo;
        }).collect(Collectors.toList());
    };

    private static void saveSamlKeys(List<KeystorePojo> keys) throws Exception{
        for (KeystorePojo k : keys) {
            String fileName = k.getFileName();
            KeyStore ks = KeyStore.getInstance("BCFKS","BCFIPS");
            ks.load(null, null);
            PrivateKey privateKey = Utils.loadRSAPrivateKey(k.getSpPrivateKey());
            Certificate certificate = Utils.loadCertificate(k.getSpCertificate());
            boolean valid = Utils.validateKeyPair(certificate.getPublicKey(),privateKey);
            ks.setKeyEntry(k.getSpKeyAlias(),privateKey,DestKeyPassword.toCharArray(),new Certificate[]{certificate});

            Certificate idpCertificate = Utils.loadCertificate(k.getIdpCertificate());
            ks.setCertificateEntry(k.getIdpCertificateAlias(),idpCertificate);

            ks.store(new FileOutputStream(fileName),DestKeyStorePasssword.toCharArray());
        }
    }


    private static void dumpSamlKeys(String fileName, List<KeystorePojo> keystores) throws Exception{
        File file = new File(fileName);
        if (file.isFile() && file.getName().equals(KeyStoreFileName)) {
            boolean hasError = false;
            KeyStore ks = KeyStore.getInstance("JKS");
            try {
                ks.load(new FileInputStream(file), KeyStorePasssword.toCharArray());
                Enumeration<String> aliases = ks.aliases();
                KeystorePojo pojo = new KeystorePojo();
                pojo.setFileName(fileName);
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    if (ks.isKeyEntry(alias)) {
                        Key key = ks.getKey(alias, KeyPassword.toCharArray());
                        Certificate certificate = ks.getCertificate(alias);
                        pojo.setSpCertificate(Base64.toBase64String(certificate.getEncoded()));
                        pojo.setSpKeyAlias(alias);
                        pojo.setSpPrivateKey(Base64.toBase64String(key.getEncoded()));
                        pojo.setSpPublicKeyId(Utils.generateJwtKid(certificate.getPublicKey()));
                        keystores.add(pojo);
                    } else if (ks.isCertificateEntry(alias)) {
                        Certificate certificate = ks.getCertificate(alias);
                        pojo.setIdpCertificate(Base64.toBase64String(certificate.getEncoded()));
                        pojo.setIdpCertificateAlias(alias);
                        pojo.setIdpPublicKeyId(Utils.generateJwtKid(certificate.getPublicKey()));
                        keystores.add(pojo);
                    }
                }
            }catch (Exception e) {
                System.out.println("Unable to load key store at " + fileName);
            }
        }

        if (file.isDirectory()){
            File[] filesList = file.listFiles();
            if (filesList == null) filesList = new File[0];
            for (File f : filesList)
                dumpSamlKeys(f.getAbsolutePath(),keystores);
        }

    }

    public static void main(String []args) throws Exception{
        Security.addProvider(new BouncyCastleFipsProvider());
        Security.addProvider(new BouncyCastleJsseProvider());
        List<KeystorePojo> ksp = new ArrayList<>();
        String sourceBaseDirectory = "/Users/sdas/work/keycloak-fips/keycloak-upstream/testsuite/integration-arquillian/tests/base/src/test/resources/adapter-test/keycloak-saml";
        String destinationBaseDirectory = "/Users/sdas/work/keycloak-fips/kc-saml/testsuite/integration-arquillian/tests/base/src/test/resources/adapter-test/keycloak-saml";
        String samlOriginal = "/Users/sdas/work/keycloak-fips/kc-saml/samloriginal.json";
        String samlFinal = "/Users/sdas/work/keycloak-fips/kc-saml/samlfinal.json";
        String samlMappings = "/Users/sdas/work/keycloak-fips/kc-saml/mappings.json";
        dumpSamlKeys(sourceBaseDirectory,ksp);
        ObjectMapper mapper = new ObjectMapper();

        mapper.writerWithDefaultPrettyPrinter().writeValue(new File(samlOriginal),ksp);
        // List of files that have the same SP key
        Set<String> keyIds = new HashSet<>();

        for (KeystorePojo k : ksp) {
            keyIds.add(k.getSpPublicKeyId());
            keyIds.add(k.getIdpPublicKeyId());
        }

        Map<String, KeyPair> replacements = new HashMap<>();
        for (String keyId : keyIds)
            replacements.put(keyId,Utils.generateKeyPair());

        Map<String,Mapping> mappings = new HashMap<>();
        for (KeystorePojo k : ksp) {
            String spPubKid = k.getSpPublicKeyId();
            String spPrvKey = k.getSpPrivateKey();
            String spPubKey = Base64.toBase64String(Utils.loadCertificate(k.getSpCertificate()).getPublicKey().getEncoded());
            String idpPubKid = k.getIdpPublicKeyId();
            String idpPrvKey = k.getIdpPrivateKey();
            String idpPubKey = Base64.toBase64String(Utils.loadCertificate(k.getIdpCertificate()).getPublicKey().getEncoded());
            if (!mappings.containsKey(spPubKid)) {
                Mapping mapping = new Mapping();
                mapping.setKeyId(spPubKid);
                mapping.setOriginalPrivateKey(spPrvKey);
                mapping.setOriginalPublicKey(spPubKey);
                mapping.setFinalPrivateKey(Base64.toBase64String(replacements.get(spPubKid).getPrivate().getEncoded()));
                mapping.setFinalPublicKey(Base64.toBase64String(replacements.get(spPubKid).getPublic().getEncoded()));
                mappings.put(spPubKid,mapping);
            }
            if (!mappings.containsKey(idpPubKid)) {
                Mapping mapping = new Mapping();
                mapping.setKeyId(idpPubKid);
                mapping.setOriginalPrivateKey(idpPrvKey);
                mapping.setOriginalPublicKey(idpPubKey);
                mapping.setFinalPrivateKey(Base64.toBase64String(replacements.get(idpPubKid).getPrivate().getEncoded()));
                mapping.setFinalPublicKey(Base64.toBase64String(replacements.get(idpPubKid).getPublic().getEncoded()));
                mappings.put(idpPubKid,mapping);
            }
        }
        mapper.writerWithDefaultPrettyPrinter().writeValue(new File(samlMappings),mappings);

        List<KeystorePojo> output = transformOutputPaths(transformSamlKeys(ksp,replacements),sourceBaseDirectory,destinationBaseDirectory);
        mapper.writerWithDefaultPrettyPrinter().writeValue(new File(samlFinal),output);
        saveSamlKeys(output);

        System.out.println("Done");
    }
}
