package com.safevault.integrity;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;

public class Lab7Runner {
    public static void main(String[] args) throws Exception {
        HexFormat hex = HexFormat.of().withUpperCase();

        System.out.println("=== ЧАСТИНА 1. КРИПТОГРАФІЧНІ ЕКСПЕРИМЕНТИ (ЗАВДАННЯ 2-11) ===");
        String msg1 = "2026_КБЗІ-23-1_Bereziuk_Oleksandr_варіант: 02";
        String msg2 = "2026_КБЗІ-23-1_Bereziuk_Oleksandr_варіант: 03";

        // Завдання 3-4: SHA-256 та лавинний ефект
        IntegrityProtectionService defaultService = new IntegrityProtectionService();
        String hash1 = defaultService.computeSha256Hex(msg1);
        String hash2 = defaultService.computeSha256Hex(msg2);
        int shaDiffBits = countDifferingBits(hex.parseHex(hash1), hex.parseHex(hash2));

        System.out.println("\n--- 1.1. Дослідження SHA-256 (Завдання 2-4) ---");
        System.out.println("Початковий рядок:  " + msg1);
        System.out.println("Хеш №1 (SHA-256):  " + hash1);
        System.out.println("Змінений рядок:    " + msg2);
        System.out.println("Хеш №2 (SHA-256):  " + hash2);
        System.out.printf("Змінено бітів у SHA-256: %d із 256 (%.1f%%)%n", shaDiffBits, (shaDiffBits / 256.0) * 100);

        // Завдання 5-9: HMAC-SHA256
        byte[] key1Bytes = hex.parseHex("4F8A2C91E7B305D6A1C8E4F29B7D3058E2A6C9F14B8D2073C5E9A1F47B2D6089");
        IntegrityProtectionService hmacService1 = new IntegrityProtectionService(key1Bytes);
        String hmac1 = hmacService1.computeHmacHex(msg1);
        boolean checkTamperedMsg = hmacService1.verifyHmac(msg2, hmac1);

        // Зміна 1 біта у першому байті ключа (0x4F ^ 0x01 = 0x4E)
        byte[] key2Bytes = Arrays.copyOf(key1Bytes, key1Bytes.length);
        key2Bytes[0] ^= 0x01;
        IntegrityProtectionService hmacService2 = new IntegrityProtectionService(key2Bytes);
        boolean checkTamperedKey = hmacService2.verifyHmac(msg1, hmac1);
        String hmac2 = hmacService2.computeHmacHex(msg1);
        int hmacDiffBits = countDifferingBits(hex.parseHex(hmac1), hex.parseHex(hmac2));

        System.out.println("\n--- 1.2. Дослідження HMAC-SHA256 (Завдання 5-9) ---");
        System.out.println("Ключ №1 (256 біт, Hex):              " + hex.formatHex(key1Bytes));
        System.out.println("HMAC №1 (для початкового рядка):     " + hmac1);
        System.out.println("Перевірка зміненого рядка проти №1:  " + checkTamperedMsg);
        System.out.println("Ключ №2 (змінено 1 біт):             " + hex.formatHex(key2Bytes));
        System.out.println("Перевірка HMAC №1 із Ключем №2:      " + checkTamperedKey);
        System.out.println("HMAC №2 (оригінал + Ключ №2):        " + hmac2);
        System.out.printf("Змінено бітів між HMAC №1 та №2: %d із 256 (%.1f%%)%n", hmacDiffBits, (hmacDiffBits / 256.0) * 100);

        // Завдання 10-11: AES-256-GCM
        byte[] aesKeyBytes = hex.parseHex("9C3E7A15D8B2406F1A5C9E37B4D82061F3A7C1E59B2D4086A2C6E0F48B3D7195");
        byte[] nonceBytes = hex.parseHex("A1B2C3D4E5F60718293A4B5C");

        Cipher gcmEncryptor = Cipher.getInstance("AES/GCM/NoPadding");
        gcmEncryptor.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKeyBytes, "AES"), new GCMParameterSpec(128, nonceBytes));
        byte[] ctWithTag = gcmEncryptor.doFinal(msg1.getBytes(StandardCharsets.UTF_8));
        byte[] ciphertext = Arrays.copyOfRange(ctWithTag, 0, ctWithTag.length - 16);
        byte[] authTag = Arrays.copyOfRange(ctWithTag, ctWithTag.length - 16, ctWithTag.length);

        System.out.println("\n--- 1.3. Дослідження AES-256-GCM (Завдання 10-11) ---");
        System.out.println("AES Ключ (256 біт, Hex):  " + hex.formatHex(aesKeyBytes));
        System.out.println("Nonce / IV (96 біт, Hex): " + hex.formatHex(nonceBytes));
        System.out.println("Шифротекст (Hex):         " + hex.formatHex(ciphertext));
        System.out.println("Auth Tag (128 біт, Hex):  " + hex.formatHex(authTag));

        // Зміна 1 байта шифротексту
        byte[] tamperedCtWithTag = Arrays.copyOf(ctWithTag, ctWithTag.length);
        tamperedCtWithTag[0] ^= 0x01;
        try {
            Cipher gcmDecryptor = Cipher.getInstance("AES/GCM/NoPadding");
            gcmDecryptor.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKeyBytes, "AES"), new GCMParameterSpec(128, nonceBytes));
            gcmDecryptor.doFinal(tamperedCtWithTag);
        } catch (AEADBadTagException e) {
            System.out.println("Спроба розшифрування модифікованого шифротексту: ВІДХИЛЕНО (" + e.getClass().getSimpleName() + ": " + e.getMessage() + ")");
        }

        System.out.println("\n=== ЧАСТИНА 2. ПЕРЕВІРКА ЦІЛІСНОСТІ ДАНИХ У SAFEVAULT (ЗАВДАННЯ 17-18) ===");
        IntegrityProtectionService vaultIntegrity = new IntegrityProtectionService();
        String noteId = "note-77a9-4b12";
        String ownerId = "user-bereziuk-02";
        int remainingViews = 1;
        String expiresAt = "2026-11-23T20:00:00Z";
        boolean requiresMfa = true;

        String canonicalPayload = vaultIntegrity.buildCanonicalNoteString(noteId, ownerId, remainingViews, expiresAt, requiresMfa);
        String storedIntegrityHmac = vaultIntegrity.computeHmacHex(canonicalPayload);
        System.out.println("Створено запис нотатки (" + noteId + "), IntegrityHmac: " + storedIntegrityHmac);

        // Штатна перевірка незміненого запису
        vaultIntegrity.enforceRecordIntegrity(noteId, ownerId, remainingViews, expiresAt, requiresMfa, storedIntegrityHmac);
        System.out.println("[ALLOW] Штатна перевірка цілісності пройшла успішно (integrityValid: true)");

        // Навмисна модифікація в обхід бізнес-логіки: підміна remainingViews з 1 на 99 та вимкнення requiresMfa
        try {
            vaultIntegrity.enforceRecordIntegrity(noteId, ownerId, 99, expiresAt, false, storedIntegrityHmac);
        } catch (SecurityException e) {
            System.out.println("[BLOCKED] Виявлено підміну полів нотатки в БД -> " + e.getMessage());
        }
    }

    private static int countDifferingBits(byte[] a, byte[] b) {
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff += Integer.bitCount((a[i] ^ b[i]) & 0xFF);
        }
        return diff;
    }
}