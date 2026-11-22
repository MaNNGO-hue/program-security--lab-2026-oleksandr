package com.safevault.auth;

import java.util.UUID;

public class UserAccount {
    private final UUID id;
    private final String username;
    private final String passwordHash;
    private final String role; // ROLE_USER или ROLE_ADMIN
    private final String totpSecret; // null, если МФА не включена

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
