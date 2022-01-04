package org.model;

public class KeystorePojo {
    String FileName;
    String SpKeyAlias;
    String SpPrivateKey;
    String SpPublicKeyId;
    String SpCertificate;
    String IdpCertificateAlias;
    String IdpCertificate;
    String IdpPrivateKey;
    String IdpPublicKeyId;

    public String getFileName() {
        return FileName;
    }

    public void setFileName(String fileName) {
        FileName = fileName;
    }

    public String getSpKeyAlias() {
        return SpKeyAlias;
    }

    public void setSpKeyAlias(String spKeyAlias) {
        SpKeyAlias = spKeyAlias;
    }

    public String getSpPrivateKey() {
        return SpPrivateKey;
    }

    public void setSpPrivateKey(String spPrivateKey) {
        SpPrivateKey = spPrivateKey;
    }

    public String getSpCertificate() {
        return SpCertificate;
    }

    public void setSpCertificate(String spCertificate) {
        SpCertificate = spCertificate;
    }

    public String getIdpCertificateAlias() {
        return IdpCertificateAlias;
    }

    public void setIdpCertificateAlias(String idpCertificateAlias) {
        IdpCertificateAlias = idpCertificateAlias;
    }

    public String getIdpCertificate() {
        return IdpCertificate;
    }

    public void setIdpCertificate(String idpCertificate) {
        IdpCertificate = idpCertificate;
    }

    public String getSpPublicKeyId() {
        return SpPublicKeyId;
    }

    public void setSpPublicKeyId(String spPublicKeyId) {
        SpPublicKeyId = spPublicKeyId;
    }

    public String getIdpPublicKeyId() {
        return IdpPublicKeyId;
    }

    public void setIdpPublicKeyId(String idpPublicKeyId) {
        IdpPublicKeyId = idpPublicKeyId;
    }

    public String getIdpPrivateKey() {
        return IdpPrivateKey;
    }

    public void setIdpPrivateKey(String idpPrivateKey) {
        IdpPrivateKey = idpPrivateKey;
    }
}
