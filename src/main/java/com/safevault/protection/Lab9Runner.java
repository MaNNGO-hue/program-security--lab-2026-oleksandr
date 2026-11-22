package com.safevault.protection;

public class Lab9Runner {
    public static void main(String[] args) {
        ObfuscatedVaultGuard guard = new ObfuscatedVaultGuard();

        String validControlValue = "2026_КБЗІ-23-1_Bereziuk_Oleksandr_варіант: 02";
        String wrongControlValue = "2026_КБЗІ-23-1_Bereziuk_Oleksandr_варіант: 99";

        System.out.println("=== ЧАСТИНА 1. ПЕРЕВІРКА ТОТОЖНОСТІ ЛОГІКИ ПОЧАТКОВОЇ ТА ОБФУСКОВАНИХ РЕАЛІЗАЦІЙ ===");
        System.out.println("Контрольне значення варіанта: " + validControlValue);

        System.out.println("\n[1] Відкрита реалізація (Baseline):");
        System.out.println("  Невірний ввід  -> " + (guard.verifyPlainBaseline(wrongControlValue) ? "Доступ дозволено" : "Доступ заборонено"));
        System.out.println("  Вірний ввід    -> " + (guard.verifyPlainBaseline(validControlValue) ? "Доступ дозволено" : "Доступ заборонено"));

        System.out.println("\n[2] Обфускація ідентифікаторів та XOR-маскування констант:");
        System.out.println("  Невірний ввід  -> " + (guard._0x4a91_verifyXorMasked(wrongControlValue) ? "Доступ дозволено" : "Доступ заборонено"));
        System.out.println("  Вірний ввід    -> " + (guard._0x4a91_verifyXorMasked(validControlValue) ? "Доступ дозволено" : "Доступ заборонено"));

        System.out.println("\n[3] Глибока обфускація (Control-Flow Flattening + AES-256-GCM + Reflection + Anti-Debug):");
        System.out.println("  Невірний ввід  -> " + (guard._0x7f3a_verifyProtected(wrongControlValue) ? "Доступ дозволено" : "Доступ заборонено"));
        System.out.println("  Вірний ввід    -> " + (guard._0x7f3a_verifyProtected(validControlValue) ? "Доступ дозволено" : "Доступ заборонено"));

        System.out.println("\n=== ЧАСТИНА 2. ПРОТИДІЯ ДИНАМІЧНОМУ АНАЛІЗУ ТА КОНТРОЛЬ ЦІЛІСНОСТІ БАЙТ-КОДУ SAFEVAULT ===");
        boolean debuggerDetected = AntiDebugAndIntegrityGuard.isDebuggerOrAgentAttached();
        String bytecodeSha256 = AntiDebugAndIntegrityGuard.computeClassBytecodeSha256(ObfuscatedVaultGuard.class);

        System.out.println("Перевірка налагоджувача (JDWP / Xdebug / JavaAgent): " + (debuggerDetected ? "ВИЯВЛЕНО" : "Не виявлено (штатне середовище)"));
        System.out.println("SHA-256 байт-коду ObfuscatedVaultGuard.class:        " + bytecodeSha256);

        // Штатна перевірка цілісності власного байт-коду
        AntiDebugAndIntegrityGuard.enforceRuntimeEnvironment(ObfuscatedVaultGuard.class, bytecodeSha256);
        System.out.println("[ALLOW] Цілісність байт-коду підтверджено, середовище виконання довірене.");

        // Імітація модифікації (патчингу) скомпільованого класу
        try {
            AntiDebugAndIntegrityGuard.enforceRuntimeEnvironment(ObfuscatedVaultGuard.class, "0000000000000000000000000000000000000000000000000000000000000000");
        } catch (SecurityException e) {
            System.out.println("[BLOCKED] Реакція на патчинг байт-коду -> " + e.getMessage());
        }
    }
}