package com.safevault.crypto;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class CryptoConfig {
    public static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    public static final int KEY_SIZE_BITS = 256;
    public static final int GCM_IV_LENGTH_BYTES = 12;   // 96 біт
    public static final int GCM_TAG_LENGTH_BITS = 128;  // 128 біт

    private final Map<String, SecretKey> keyRing = new ConcurrentHashMap<>();
    private volatile String activeKeyVersion;

    public CryptoConfig() {
        String envKeyBase64 = System.getenv("SAFEVAULT_MASTER_KEY");
        SecretKey initialKey = (envKeyBase64 != null && !envKeyBase64.isBlank())
                ? new SecretKeySpec(Base64.getDecoder().decode(envKeyBase64), "AES")
                : generateRandomAes256Key();
        this.activeKeyVersion = "v1";
        this.keyRing.put(activeKeyVersion, initialKey);
    }

    public SecretKey getActiveKey() {
        return keyRing.get(activeKeyVersion);
    }

    public String getActiveKeyVersion() {
        return activeKeyVersion;
    }

    public SecretKey getKeyByVersion(String version) {
        SecretKey key = keyRing.get(version);
        if (key == null) {
            throw new SecurityException("Невідома версія ключа шифрування: " + version);
        }
        return key;
    }

    public String rotateKey() {
        int nextNum = keyRing.size() + 1;
        String newVersion = "v" + nextNum;
        keyRing.put(newVersion, generateRandomAes256Key());
        this.activeKeyVersion = newVersion;
        return newVersion;
    }

    private SecretKey generateRandomAes256Key() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(KEY_SIZE_BITS, new SecureRandom());
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("AES-256 недоступний у середовищі JVM", e);
        }
    }
}