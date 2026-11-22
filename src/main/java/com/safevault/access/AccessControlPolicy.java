package com.safevault.access;

import java.time.Instant;

public class AccessControlPolicy {

    public void checkCreateNote(AccessContext subject) {
        if (subject == null || !subject.isAuthenticated()) {
            throw new SecurityException("401 Unauthorized: Створення нотаток дозволено лише автентифікованим користувачам");
        }
    }

    public void checkReadNote(AccessContext subject, SecretNoteResource note, String providedTokenHash, Instant now) {
        if (note == null || !note.getAccessTokenHash().equals(providedTokenHash)) {
            throw new SecurityException("403 Forbidden: Недійсний токен доступу до нотатки");
        }
        if (!now.isBefore(note.getExpiresAt())) {
            note.markExpired();
            throw new SecurityException("410 Gone: Термін дії нотатки вичерпано (EXPIRED)");
        }
        if (note.getStatus() != SecretNoteResource.Status.ACTIVE || note.getRemainingViews() <= 0) {
            throw new SecurityException("410 Gone: Нотатка недоступна або вже знищена (" + note.getStatus() + ")");
        }
        if (note.isRequiresMfa() && (subject == null || !subject.mfaAuthenticated())) {
            throw new SecurityException("403 Forbidden: Для читання конфіденційної нотатки потрібна МФА-автентифікація");
        }
    }

    public void checkRevokeNote(AccessContext subject, SecretNoteResource note) {
        if (subject == null || !subject.isAuthenticated()) {
            throw new SecurityException("401 Unauthorized: Потрібна автентифікація");
        }
        if (!note.getOwnerId().equals(subject.userId())) {
            throw new SecurityException("403 Forbidden: Користувач " + subject.username() + " не є власником нотатки");
        }
        if (note.getStatus() != SecretNoteResource.Status.ACTIVE) {
            throw new SecurityException("410 Gone: Неможливо відкликати нотатку у стані " + note.getStatus());
        }
    }

    public void checkViewAuditLogs(AccessContext subject) {
        if (subject == null || !"ROLE_ADMIN".equals(subject.role())) {
            throw new SecurityException("403 Forbidden: Доступ до журналу аудиту дозволено лише для ROLE_ADMIN");
        }
        if (!subject.mfaAuthenticated()) {
            throw new SecurityException("403 Forbidden: Адміністратору потрібна підтверджена МФА-сесія");
        }
    }
}