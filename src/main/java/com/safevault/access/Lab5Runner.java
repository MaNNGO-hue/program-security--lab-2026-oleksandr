package com.safevault.access;

import java.util.UUID;

public class Lab5Runner {
    public static void main(String[] args) {
        VaultProtectedService vaultService = new VaultProtectedService();

        AccessContext ownerOleksandr = new AccessContext(UUID.randomUUID(), "oleksandr", "ROLE_USER", true);
        AccessContext otherUser = new AccessContext(UUID.randomUUID(), "ivan_user", "ROLE_USER", false);
        AccessContext adminWithMfa = new AccessContext(UUID.randomUUID(), "sec_admin", "ROLE_ADMIN", true);
        AccessContext adminNoMfa = new AccessContext(UUID.randomUUID(), "sec_admin_nomfa", "ROLE_ADMIN", false);

        System.out.println("=== СЦЕНАРІЙ 1. СТВОРЕННЯ ТА ЧИТАННЯ НОТАТКИ (ABAC + МФА) ===");
        SecretNoteResource note1 = vaultService.createNote(
                ownerOleksandr, "token-secret-1", "DB_PASSWORD=SuperSecret2026", 1, 300, true
        );
        System.out.println("[ALLOW] Користувач oleksandr створив нотатку: " + note1.getNoteId());

        try {
            vaultService.readNote(otherUser, note1, "token-secret-1");
        } catch (SecurityException e) {
            System.out.println("[DENY] Читання без МФА -> " + e.getMessage());
        }

        String decrypted = vaultService.readNote(ownerOleksandr, note1, "token-secret-1");
        System.out.println("[ALLOW] Успішне читання з МФА -> Отримано: " + decrypted + " (статус: " + note1.getStatus() + ")");

        try {
            vaultService.readNote(ownerOleksandr, note1, "token-secret-1");
        } catch (SecurityException e) {
            System.out.println("[DENY] Повторне читання знищеної нотатки -> " + e.getMessage());
        }

        System.out.println("\n=== СЦЕНАРІЙ 2. КОНТРОЛЬ ВЛАСНИКА ПРИ ВІДКЛИКАННІ (OWNERSHIP) ===");
        SecretNoteResource note2 = vaultService.createNote(
                ownerOleksandr, "token-secret-2", "API_KEY=xyz-987", 3, 600, false
        );

        try {
            vaultService.revokeNote(otherUser, note2);
        } catch (SecurityException e) {
            System.out.println("[DENY] Спроба відкликання чужої нотатки -> " + e.getMessage());
        }

        vaultService.revokeNote(ownerOleksandr, note2);
        System.out.println("[ALLOW] Власник oleksandr відкликав нотатку -> статус: " + note2.getStatus());

        System.out.println("\n=== СЦЕНАРІЙ 3. РОЛЬОВИЙ ДОСТУП ДО ЖУРНАЛУ АУДИТУ (RBAC + МФА) ===");
        try {
            vaultService.getAuditLogs(ownerOleksandr);
        } catch (SecurityException e) {
            System.out.println("[DENY] ROLE_USER запитує аудит -> " + e.getMessage());
        }

        try {
            vaultService.getAuditLogs(adminNoMfa);
        } catch (SecurityException e) {
            System.out.println("[DENY] ROLE_ADMIN без МФА запитує аудит -> " + e.getMessage());
        }

        System.out.println("[ALLOW] ROLE_ADMIN із МФА отримав журнал аудиту (" + vaultService.getAuditLogs(adminWithMfa).size() + " записів):");
        vaultService.getAuditLogs(adminWithMfa).forEach(log -> System.out.println("   " + log));
    }
}