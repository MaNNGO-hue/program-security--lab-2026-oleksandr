package com.safevault.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

public class VaultEncryptionService {
    private final CryptoConfig cryptoConfig;
    private final SecureRandom secureRandom = new SecureRandom();

    public VaultEncryptionService(CryptoConfig cryptoConfig) {
        this.cryptoConfig = cryptoConfig;
    }

    public String encrypt(String plainText) {
        try {
            byte[] nonce = new byte[CryptoConfig.GCM_IV_LENGTH_BYTES];
            secureRandom.nextBytes(nonce);

            String keyVersion = cryptoConfig.getActiveKeyVersion();
            SecretKey key = cryptoConfig.getActiveKey();

            Cipher cipher = Cipher.getInstance(CryptoConfig.CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(CryptoConfig.GCM_TAG_LENGTH_BITS, nonce));

            byte[] cipherTextWithTag = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            ByteBuffer buffer = ByteBuffer.allocate(nonce.length + cipherTextWithTag.length);
            buffer.put(nonce);
            buffer.put(cipherTextWithTag);

            return keyVersion + ":" + Base64.getEncoder().encodeToString(buffer.array());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Помилка шифрування AES-256-GCM", e);
        }
    }

    public String decrypt(String encryptedPayload) {
        try {
            String[] parts = encryptedPayload.split(":", 2);
            if (parts.length != 2) {
                throw new SecurityException("Некоректний формат зашифрованого пакета");
            }
            SecretKey key = cryptoConfig.getKeyByVersion(parts[0]);
            byte[] decoded = Base64.getDecoder().decode(parts[1]);

            if (decoded.length < CryptoConfig.GCM_IV_LENGTH_BYTES + 16) {
                throw new SecurityException("Пошкоджений шифротекст: недостатня довжина пакета");
            }

            byte[] nonce = new byte[CryptoConfig.GCM_IV_LENGTH_BYTES];
            byte[] cipherTextWithTag = new byte[decoded.length - CryptoConfig.GCM_IV_LENGTH_BYTES];
            System.arraycopy(decoded, 0, nonce, 0, nonce.length);
            System.arraycopy(decoded, nonce.length, cipherTextWithTag, 0, cipherTextWithTag.length);

            Cipher cipher = Cipher.getInstance(CryptoConfig.CIPHER_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(CryptoConfig.GCM_TAG_LENGTH_BITS, nonce));

            byte[] plainBytes = cipher.doFinal(cipherTextWithTag);
            return new String(plainBytes, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new SecurityException("Помилка перевірки цілісності або розшифрування (AEAD Tag Mismatch): " + e.getMessage(), e);
        }
    }
}