package com.mcafee;

import org.Utils;

import java.security.KeyPair;
import java.util.Base64;

public class RSABCGenerator {
    public static void main(String[] args) throws Exception {
        KeyPair kp = Utils.createKeyPair();

        System.out.println(new String(Base64.getEncoder().encode(kp.getPrivate().getEncoded())));
        System.out.println(new String(Base64.getEncoder().encode(kp.getPublic().getEncoded())));
    }
}
