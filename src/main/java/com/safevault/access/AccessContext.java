package com.safevault.access;

import java.util.UUID;

public record AccessContext(
        UUID userId,
        String username,
        String role,
        boolean mfaAuthenticated
) {
    public boolean isAuthenticated() {
        return userId != null;
    }
}