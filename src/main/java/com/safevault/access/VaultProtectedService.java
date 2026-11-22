package com.safevault.access;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

public class VaultProtectedService {
    private final AccessControlPolicy policy = new AccessControlPolicy();
    private final List<String> auditLogs = new ArrayList<>();

    public SecretNoteResource createNote(AccessContext subject, String rawToken, String secretText,
                                         int maxViews, int ttlSeconds, boolean requiresMfa) {
        policy.checkCreateNote(subject);
        String tokenHash = sha256(rawToken);
        SecretNoteResource note = new SecretNoteResource(
                subject.userId(), tokenHash, "ENC(" + secretText + ")",
                maxViews, Instant.now().plusSeconds(ttlSeconds), requiresMfa
        );
        auditLogs.add("[CREATED] noteId=" + note.getNoteId() + " by user=" + subject.username());
        return note;
    }

    public String readNote(AccessContext subject, SecretNoteResource note, String rawToken) {
        policy.checkReadNote(subject, note, sha256(rawToken), Instant.now());
        String content = note.getEncryptedContent();
        note.consumeOneView();
        auditLogs.add("[ACCESSED] noteId=" + note.getNoteId() + ", status=" + note.getStatus());
        return content;
    }

    public void revokeNote(AccessContext subject, SecretNoteResource note) {
        policy.checkRevokeNote(subject, note);
        note.markRevoked();
        auditLogs.add("[REVOKED] noteId=" + note.getNoteId() + " by owner=" + subject.username());
    }

    public List<String> getAuditLogs(AccessContext subject) {
        policy.checkViewAuditLogs(subject);
        return List.copyOf(auditLogs);
    }

    private String sha256(String value) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}