package com.safevault.auth;

import java.util.UUID;

public class UserAccount {
    private final UUID id;
    private final String username;
    private final String passwordHash;
    private final String role;
    private final String totpSecret;

    public UserAccount(String username, String passwordHash, String role, String totpSecret) {
        this.id = UUID.randomUUID();
        this.username = username;
        this.passwordHash = passwordHash;
        this.role = role;
        this.totpSecret = totpSecret;
    }

    public UUID getId() { return id; }
    public String getUsername() { return username; }
    public String getPasswordHash() { return passwordHash; }
    public String getRole() { return role; }
    public String getTotpSecret() { return totpSecret; }
}