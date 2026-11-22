package com.safevault.access;

import java.time.Instant;
import java.util.UUID;

public class SecretNoteResource {
    public enum Status { ACTIVE, CONSUMED, EXPIRED, REVOKED }

    private final UUID noteId;
    private final UUID ownerId;
    private final String accessTokenHash;
    private String encryptedContent;
    private int remainingViews;
    private final Instant expiresAt;
    private final boolean requiresMfa;
    private Status status;

    public SecretNoteResource(UUID ownerId, String accessTokenHash, String encryptedContent,
                              int maxViews, Instant expiresAt, boolean requiresMfa) {
        this.noteId = UUID.randomUUID();
        this.ownerId = ownerId;
        this.accessTokenHash = accessTokenHash;
        this.encryptedContent = encryptedContent;
        this.remainingViews = maxViews;
        this.expiresAt = expiresAt;
        this.requiresMfa = requiresMfa;
        this.status = Status.ACTIVE;
    }

    public UUID getNoteId() { return noteId; }
    public UUID getOwnerId() { return ownerId; }
    public String getAccessTokenHash() { return accessTokenHash; }
    public String getEncryptedContent() { return encryptedContent; }
    public int getRemainingViews() { return remainingViews; }
    public Instant getExpiresAt() { return expiresAt; }
    public boolean isRequiresMfa() { return requiresMfa; }
    public Status getStatus() { return status; }

    public void consumeOneView() {
        this.remainingViews--;
        if (this.remainingViews <= 0) {
            this.status = Status.CONSUMED;
            this.encryptedContent = null;
        }
    }

    public void markExpired() {
        this.status = Status.EXPIRED;
        this.encryptedContent = null;
    }

    public void markRevoked() {
        this.status = Status.REVOKED;
        this.encryptedContent = null;
    }
}