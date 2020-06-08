package com.accedia.apple.auth.key;

import com.google.common.io.ByteStreams;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class AppleClientPrivateKeyFactory {

    private final static String KEY_HEADER = "-----BEGIN PRIVATE KEY-----";
    private final static String KEY_FOOTER = "-----END PRIVATE KEY-----";
    private final KeyFactory eclipticCurve;

    public AppleClientPrivateKeyFactory() {
        try {
            this.eclipticCurve = KeyFactory.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public ECPrivateKey getEcPrivateKey(InputStream privateKeyFileStream) throws IOException, InvalidKeySpecException {
        String privateKeyFileString = new String(ByteStreams.toByteArray(privateKeyFileStream));
        return getEcPrivateKey(privateKeyFileString);
    }

    public ECPrivateKey getEcPrivateKey(String privateKeyFileString) throws InvalidKeySpecException {
        String privateKeyEncodedString = privateKeyFileString
                .replaceAll(KEY_FOOTER,"")
                .replaceAll(KEY_HEADER, "")
                .replaceAll("\n","");

        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyEncodedString);
        KeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return (ECPrivateKey)eclipticCurve.generatePrivate(keySpec);
    }
}