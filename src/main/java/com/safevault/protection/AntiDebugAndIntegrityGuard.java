package com.safevault.protection;

import java.io.InputStream;
import java.lang.management.ManagementFactory;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;

public final class AntiDebugAndIntegrityGuard {
    private AntiDebugAndIntegrityGuard() {
    }

    // Виявлення ознак підключеного налагоджувача або сторонньої інструментації JVM (JDWP / Xdebug / зовнішній JavaAgent)
    public static boolean isDebuggerOrAgentAttached() {
        List<String> jvmArgs = ManagementFactory.getRuntimeMXBean().getInputArguments();
        for (String arg : jvmArgs) {
            String lower = arg.toLowerCase();
            if (lower.contains("jdwp") || lower.contains("xdebug")
                    || (lower.contains("javaagent") && !lower.contains("idea_rt.jar"))) {
                return true;
            }
        }
        return false;
    }

    // Обчислення SHA-256 власного скомпільованого .class файла для перевірки відсутності патчингу байт-коду
    public static String computeClassBytecodeSha256(Class<?> targetClass) {
        String classFileName = targetClass.getSimpleName() + ".class";
        try (InputStream is = targetClass.getResourceAsStream(classFileName)) {
            if (is == null) {
                throw new IllegalStateException("Не знайдено байт-код класу: " + classFileName);
            }
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytecode = is.readAllBytes();
            return HexFormat.of().withUpperCase().formatHex(digest.digest(bytecode));
        } catch (Exception e) {
            throw new SecurityException("Помилка перевірки цілісності байт-коду класу", e);
        }
    }

    public static void enforceRuntimeEnvironment(Class<?> guardedClass, String expectedSha256) {
        if (isDebuggerOrAgentAttached()) {
            throw new SecurityException("403 Forbidden: Виявлено активний налагоджувач (Debugger/JDWP)! Виконання заблоковано.");
        }
        String actualHash = computeClassBytecodeSha256(guardedClass);
        if (expectedSha256 != null && !expectedSha256.equalsIgnoreCase(actualHash)) {
            throw new SecurityException("403 Forbidden: Порушено цілісність байт-коду! Виявлено модифікацію програми.");
        }
    }
}