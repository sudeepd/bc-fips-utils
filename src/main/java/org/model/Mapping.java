package org.model;

public class Mapping {
    String keyId;
    String originalPrivateKey;
    String originalPublicKey;
    String finalPrivateKey;
    String finalPublicKey;

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getOriginalPrivateKey() {
        return originalPrivateKey;
    }

    public void setOriginalPrivateKey(String originalPrivateKey) {
        this.originalPrivateKey = originalPrivateKey;
    }

    public String getOriginalPublicKey() {
        return originalPublicKey;
    }

    public void setOriginalPublicKey(String originalPublicKey) {
        this.originalPublicKey = originalPublicKey;
    }

    public String getFinalPrivateKey() {
        return finalPrivateKey;
    }

    public void setFinalPrivateKey(String finalPrivateKey) {
        this.finalPrivateKey = finalPrivateKey;
    }

    public String getFinalPublicKey() {
        return finalPublicKey;
    }

    public void setFinalPublicKey(String finalPublicKey) {
        this.finalPublicKey = finalPublicKey;
    }
};
