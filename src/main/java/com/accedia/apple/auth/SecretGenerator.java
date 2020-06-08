package com.accedia.apple.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import java.security.interfaces.ECPrivateKey;
import java.sql.Date;
import java.time.Instant;

public class SecretGenerator {

    private static final String APPLE_AUDIENCE = "https://appleid.apple.com";

    public String generateSecret(ECPrivateKey privateKey, String keyId, String teamId, String clientId, Instant now,
                                 long tokenLifeInSeconds) {
        long epochSecNow = now.getEpochSecond();
        Instant expiresAt = Instant.ofEpochSecond(epochSecNow + tokenLifeInSeconds);
        return JWT.create()
                .withKeyId(keyId)
                .withIssuer(teamId)
                .withSubject(clientId)
                .withAudience(APPLE_AUDIENCE)
                .withIssuedAt(Date.from(now))
                .withExpiresAt(Date.from(expiresAt))
                .sign(Algorithm.ECDSA256(null, privateKey));
    }
}
