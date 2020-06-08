package com.accedia.apple.auth.user;

public enum AppleUserDataClaim {
    EMAIL("email"),
    EMAIL_VERIFIED("email_verified"),
    AUTHENTICATION_TIME("auth_time");
    private final String claimKey;

    AppleUserDataClaim(String claimKey) {
        this.claimKey = claimKey;
    }

    public String getClaimKey() {
        return claimKey;
    }
}
