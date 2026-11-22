package com.safevault.licensing;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;

public class LicenseVerificationService {
    private static final String EXPECTED_PRODUCT_ID = "SafeVault";
    private final PublicKey developerPublicKey;

    public LicenseVerificationService(String publicKeyPem) {
        this.developerPublicKey = parseRsaPublicKey(publicKeyPem);
    }

    public LicensePayload verifyAndLoadLicense(byte[] licenseJsonBytes, byte[] signatureBytes, Instant now) {
        if (!verifyRsaPssSignature(licenseJsonBytes, signatureBytes)) {
            throw new SecurityException("403 Forbidden: Порушення ліцензійних умов або недійсний цифровий підпис ліцензії (RSA-PSS)!");
        }

        String jsonText = new String(licenseJsonBytes, StandardCharsets.UTF_8);
        LicensePayload payload = LicensePayload.fromJson(jsonText);

        if (!EXPECTED_PRODUCT_ID.equals(payload.productId())) {
            throw new SecurityException("403 Forbidden: Ліцензія призначена для іншого продукту (" + payload.productId() + ")");
        }
        if (!now.isBefore(payload.expiresAt())) {
            throw new SecurityException("403 Forbidden: Строк дії підписки ліцензії вичерпано (" + payload.expiresAt() + ")");
        }
        return payload;
    }

    public void enforceFeatureAccess(LicensePayload license, String requiredFeature, int activeUserDevices) {
        if (activeUserDevices > license.maxDevices()) {
            throw new SecurityException("403 Forbidden: Перевищено ліміт пристроїв за ліцензією (" + activeUserDevices + "/" + license.maxDevices() + ")");
        }
        if (!license.hasFeature(requiredFeature)) {
            throw new SecurityException("403 Forbidden: Функція '" + requiredFeature + "' недоступна у поточному тарифі ліцензії");
        }
    }

    private boolean verifyRsaPssSignature(byte[] data, byte[] signatureBytes) {
        try {
            Signature signature = Signature.getInstance("RSASSA-PSS");
            PSSParameterSpec pssSpec = new PSSParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1
            );
            signature.setParameter(pssSpec);
            signature.initVerify(developerPublicKey);
            signature.update(data);
            return signature.verify(signatureBytes);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    private PublicKey parseRsaPublicKey(String pem) {
        try {
            String cleanBase64 = pem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] derBytes = Base64.getDecoder().decode(cleanBase64);
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(derBytes));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Помилка завантаження відкритого ключа розробника", e);
        }
    }
}