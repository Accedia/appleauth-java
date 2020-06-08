package com.accedia.apple.auth.user;

public class AppleAuthorizationToken {
    private final String authorisationCode;
    private final long expireInSeconds;
    private final String idToken;
    private final String refreshToken;
    private final UserData userData;

    public AppleAuthorizationToken(String authorisationCode,
                                   long expireInSeconds,
                                   String idToken,
                                   String refreshToken,
                                   UserData userData) {
        this.authorisationCode = authorisationCode;
        this.expireInSeconds = expireInSeconds;
        this.idToken = idToken;
        this.refreshToken = refreshToken;
        this.userData = userData;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public String getIdToken() {
        return idToken;
    }

    public long getExpireInSeconds() {
        return expireInSeconds;
    }

    public String getAuthorisationCode() {
        return authorisationCode;
    }

    public UserData getUserData() {
        return userData;
    }
}
