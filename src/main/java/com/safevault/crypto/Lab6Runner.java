package com.safevault.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;

public class Lab6Runner {
    public static void main(String[] args) throws Exception {
        System.out.println("=== ЧАСТИНА 1. ДОСЛІДЖЕННЯ ВРАЗЛИВОСТІ AES-CTR (BIT-FLIPPING / XOR ATTACK) ===");
        String p1 = "2026_КБЗІ-23-1_Bereziuk_Oleksandr_варіант: 02";
        String p2 = "2026_КБЗІ-23-1_Bereziuk_Oleksandr_варіант: 99";

        byte[] keyBytes = HexFormat.of().parseHex("7a9f3c1e8b4d2056a1c4e9f23b6d80145e7a9c2f4b8d10367c9e2a4f6b8d0135");
        byte[] ivBytes = HexFormat.of().parseHex("102030405060708090a0b0c0d0e0f012");

        Cipher ctrEncryptor = Cipher.getInstance("AES/CTR/NoPadding");
        ctrEncryptor.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), new IvParameterSpec(ivBytes));

        byte[] p1Bytes = p1.getBytes(StandardCharsets.UTF_8);
        byte[] c1Bytes = ctrEncryptor.doFinal(p1Bytes);
        byte[] gammaBytes = xor(c1Bytes, p1Bytes);

        byte[] p2Bytes = p2.getBytes(StandardCharsets.UTF_8);
        byte[] c2Bytes = xor(gammaBytes, p2Bytes);

        Cipher ctrDecryptor = Cipher.getInstance("AES/CTR/NoPadding");
        ctrDecryptor.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), new IvParameterSpec(ivBytes));
        String decryptedC2 = new String(ctrDecryptor.doFinal(c2Bytes), StandardCharsets.UTF_8);

        System.out.println("Початковий рядок (P1):      " + p1);
        System.out.println("Шифротекст №1 (C1, HEX):    " + HexFormat.of().formatHex(c1Bytes));
        System.out.println("Гама №1 (C1 XOR P1, HEX):   " + HexFormat.of().formatHex(gammaBytes));
        System.out.println("Шифротекст №2 (C2, HEX):    " + HexFormat.of().formatHex(c2Bytes));
        System.out.println("Результат розшифрування C2: " + decryptedC2);

        System.out.println("\n=== ЧАСТИНА 2. АВТЕНТИФІКОВАНЕ ШИФРУВАННЯ SAFEVAULT (AES-256-GCM) ===");
        CryptoConfig config = new CryptoConfig();
        VaultEncryptionService encryptionService = new VaultEncryptionService(config);

        String secretNote = "DB_PROD_TOKEN=sfv_live_9988776655_Bereziuk";
        String encrypted1 = encryptionService.encrypt(secretNote);
        String encrypted2 = encryptionService.encrypt(secretNote);

        System.out.println("Шифротекст 1 (випадковий Nonce): " + encrypted1);
        System.out.println("Шифротекст 2 (новий Nonce):      " + encrypted2);
        System.out.println("Розшифрований вміст:             " + encryptionService.decrypt(encrypted1));

        String[] parts = encrypted1.split(":", 2);
        byte[] rawPacket = Base64.getDecoder().decode(parts[1]);
        rawPacket[rawPacket.length - 1] ^= 0x01;
        String tamperedPayload = parts[0] + ":" + Base64.getEncoder().encodeToString(rawPacket);

        try {
            encryptionService.decrypt(tamperedPayload);
        } catch (SecurityException e) {
            System.out.println("[BLOCKED] Спроба модифікації шифротексту AES-GCM -> " + e.getMessage());
        }

        String newVer = config.rotateKey();
        String encryptedV2 = encryptionService.encrypt("SECRET_AFTER_ROTATION");
        System.out.println("Ротація ключів виконана -> активна версія: " + newVer);
        System.out.println("Читання старої нотатки (v1): " + encryptionService.decrypt(encrypted1));
        System.out.println("Читання нової нотатки (v2):  " + encryptionService.decrypt(encryptedV2));
    }

    private static byte[] xor(byte[] a, byte[] b) {
        byte[] res = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            res[i] = (byte) (a[i] ^ b[i]);
        }
        return res;
    }
}