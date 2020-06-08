package com.accedia.apple.auth.user;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

public class UserDataDeserializer {

    public UserData getUserDataFromIdToken(String idToken) {
        DecodedJWT decodedJWT = JWT.decode(idToken);
        Map<String, Claim> claims = decodedJWT.getClaims();
        return new UserData(
                Optional.ofNullable(claims.get(AppleUserDataClaim.EMAIL.getClaimKey()))
                        .map(Claim::asString).orElse(null),
                Optional.ofNullable(claims.get(AppleUserDataClaim.EMAIL_VERIFIED.getClaimKey()))
                        .map(Claim::asString).map(Boolean::parseBoolean).orElse(null),
                decodedJWT.getSubject(),
                Optional.ofNullable(claims.get(AppleUserDataClaim.AUTHENTICATION_TIME.getClaimKey()))
                .map(Claim::asInt)
                .map(Instant::ofEpochSecond)
                .orElse(null)
        );
    }
}
