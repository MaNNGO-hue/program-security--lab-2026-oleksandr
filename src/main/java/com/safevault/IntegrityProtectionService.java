package com.safevault.integrity;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

public class IntegrityProtectionService {
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private final SecretKey hmacSecretKey;

    public IntegrityProtectionService() {
        String envHmacKey = System.getenv("SAFEVAULT_HMAC_KEY");
        this.hmacSecretKey = (envHmacKey != null && !envHmacKey.isBlank())
                ? new SecretKeySpec(Base64.getDecoder().decode(envHmacKey), HMAC_ALGORITHM)
                : generateRandomHmacKey();
    }

    public IntegrityProtectionService(byte[] customKeyBytes) {
        this.hmacSecretKey = new SecretKeySpec(customKeyBytes, HMAC_ALGORITHM);
    }

    // Обчислення криптографічного хешу SHA-256 для контролю незмінності артефактів
    public String computeSha256Hex(String data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().withUpperCase().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 недоступний у JVM", e);
        }
    }

    // Обчислення коду автентичності повідомлення HMAC-SHA256
    public String computeHmacHex(String canonicalPayload) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(hmacSecretKey);
            byte[] rawHmac = mac.doFinal(canonicalPayload.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().withUpperCase().formatHex(rawHmac);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Помилка обчислення HMAC-SHA256", e);
        }
    }

    // Перевірка HMAC у постійному часі (захист від Timing Attacks)
    public boolean verifyHmac(String canonicalPayload, String expectedHmacHex) {
        String actualHmacHex = computeHmacHex(canonicalPayload);
        return MessageDigest.isEqual(
                actualHmacHex.getBytes(StandardCharsets.UTF_8),
                expectedHmacHex.toUpperCase().getBytes(StandardCharsets.UTF_8)
        );
    }

    // Перевірка запису нотатки SafeVault із викиданням винятку при підміні
    public void enforceRecordIntegrity(String noteId, String ownerId, int remainingViews,
                                       String expiresAt, boolean requiresMfa, String storedHmac) {
        String canonical = buildCanonicalNoteString(noteId, ownerId, remainingViews, expiresAt, requiresMfa);
        if (!verifyHmac(canonical, storedHmac)) {
            throw new SecurityException("400 Bad Request: Порушення цілісності даних! Запис нотатки " + noteId + " було несанкціоновано змінено.");
        }
    }

    public String buildCanonicalNoteString(String noteId, String ownerId, int remainingViews,
                                           String expiresAt, boolean requiresMfa) {
        return String.join("|", noteId, ownerId, String.valueOf(remainingViews), expiresAt, String.valueOf(requiresMfa));
    }

    private SecretKey generateRandomHmacKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(HMAC_ALGORITHM);
            keyGen.init(256, new SecureRandom());
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("HmacSHA256 недоступний у JVM", e);
        }
    }
}