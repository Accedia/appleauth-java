package com.accedia.apple.auth.user;

import java.time.Instant;

public class UserData {
    private final String email;
    private final Boolean isVerified;
    private final String subject;
    private final Instant authTime;

    public UserData(String email, Boolean isVerified, String subject, Instant authTime) {
        this.email = email;
        this.isVerified = isVerified;
        this.subject = subject;
        this.authTime = authTime;
    }

    public String getEmail() {
        return email;
    }

    public Boolean getVerified() {
        return isVerified;
    }

    public String getSubject() {
        return subject;
    }

    public Instant getAuthTime() {
        return authTime;
    }
}
