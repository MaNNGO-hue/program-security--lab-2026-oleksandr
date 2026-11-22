package com.safevault.licensing;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

public class Lab8Runner {
    public static void main(String[] args) throws Exception {
        Path baseDir = Path.of("src/main/resources/licensing");
        String publicKeyPem = Files.readString(baseDir.resolve("public.pem"), StandardCharsets.UTF_8);
        byte[] validLicenseBytes = Files.readAllBytes(baseDir.resolve("license.json"));
        byte[] signatureBytes = Files.readAllBytes(baseDir.resolve("license.sig"));

        LicenseVerificationService verificationService = new LicenseVerificationService(publicKeyPem);

        System.out.println("=== ЧАСТИНА 1. ПЕРЕВІРКА ВАЛІДНОЇ ЛІЦЕНЗІЇ SAFEVAULT (RSA-3072-PSS) ===");
        LicensePayload license = verificationService.verifyAndLoadLicense(
                validLicenseBytes, signatureBytes, Instant.now()
        );
        System.out.println("[ALLOW] Цифровий підпис RSA-PSS підтверджено!");
        System.out.println("  licenseId:  " + license.licenseId());
        System.out.println("  productId:  " + license.productId());
        System.out.println("  licensee:   " + license.licensee());
        System.out.println("  expiresAt:  " + license.expiresAt());
        System.out.println("  maxDevices: " + license.maxDevices());
        System.out.println("  features:   " + license.features());

        verificationService.enforceFeatureAccess(license, "MfaProtectedNotes", 2);
        System.out.println("[ALLOW] Доступ до корпоративного модуля 'MfaProtectedNotes' дозволено (пристроїв: 2/" + license.maxDevices() + ")");

        try {
            verificationService.enforceFeatureAccess(license, "UnlimitedEnterpriseCluster", 2);
        } catch (SecurityException e) {
            System.out.println("[DENY] Запит неоплаченої функції -> " + e.getMessage());
        }

        System.out.println("\n=== ЧАСТИНА 2. ІМІТАЦІЯ ПІДМІНИ ФАЙЛУ ЛІЦЕНЗІЇ (МОДИФІКАЦІЯ EXPIRES_AT) ===");
        String tamperedJson = new String(validLicenseBytes, StandardCharsets.UTF_8)
                .replace("2027-12-31T23:59:59Z", "2099-12-31T23:59:59Z");

        try {
            verificationService.verifyAndLoadLicense(
                    tamperedJson.getBytes(StandardCharsets.UTF_8), signatureBytes, Instant.now()
            );
        } catch (SecurityException e) {
            System.out.println("[BLOCKED] Виявлено втручання у license.json -> " + e.getMessage());
        }
    }
}