package com.accedia.apple.auth;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.TimeUnit;

public class AppleKeyProvider implements RSAKeyProvider {

    private static final String DEFAULT_APPLE_KEY_URL = "https://appleid.apple.com/auth/keys";
    private static final long DEFAULT_KEY_VALIDITY_IN_SEC = 60 * 60;
    private final JwkProvider jwkProvider;

    public AppleKeyProvider() {
        JwkProviderBuilder providerBuilder = new JwkProviderBuilder(DEFAULT_APPLE_KEY_URL);
        jwkProvider = providerBuilder.cached(10, DEFAULT_KEY_VALIDITY_IN_SEC, TimeUnit.SECONDS).build();
    }

    @Override
    public RSAPublicKey getPublicKeyById(String s) {
        try {
            return (RSAPublicKey) jwkProvider.get(s).getPublicKey();
        } catch (JwkException e) {
            throw new RuntimeException("Error occurred while retrieving Apple Public Keys.", e);
        }
    }

    @Override
    public RSAPrivateKey getPrivateKey() {
        throw new UnsupportedOperationException("Can't get apple private key.");
    }

    @Override
    public String getPrivateKeyId() {
        throw new UnsupportedOperationException("Can't get apple private key.");
    }
}
