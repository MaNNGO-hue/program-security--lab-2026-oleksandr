package com.safevault.auth;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

public class Lab4Runner {
    public static void main(String[] args) throws Exception {
        System.out.println("=== ЧАСТИНА 1. ОБМЕЖЕННЯ BCRYPT У 72 БАЙТИ ===");
        StringBuilder baseBuilder = new StringBuilder("2026_KBZI-23-1_Bereziuk_02_");
        while (baseBuilder.toString().getBytes(StandardCharsets.UTF_8).length < 72) {
            baseBuilder.append('_');
        }
        String str1 = baseBuilder.toString();
        String str2 = str1 + "1";
        String str3 = str1 + generateRandomString(10);
        String str4 = str1.substring(0, str1.length() - 1);

        String[] strings = {str1, str2, str3, str4};
        String[] hashes = new String[4];
        for (int i = 0; i < 4; i++) {
            hashes[i] = BCrypt.hashpw(strings[i], BCrypt.gensalt(10));
            System.out.printf("Рядок №%d (%d б.): %s%nХеш №%d: %s%n",
                    i + 1, strings[i].getBytes(StandardCharsets.UTF_8).length, strings[i], i + 1, hashes[i]);
        }

        System.out.println("\n--- Попарна перевірка хешів ---");
        for (int h = 0; h < 4; h++) {
            for (int s = 0; s < 4; s++) {
                System.out.printf("Хеш №%d vs Рядок №%d (%d б.) -> %s%n",
                        h + 1, s + 1, strings[s].getBytes(StandardCharsets.UTF_8).length,
                        BCrypt.checkpw(strings[s], hashes[h]));
            }
        }

        System.out.println("\n=== ЧАСТИНА 2. ПЕРЕБІР: SHA-256 VS BCRYPT (COST=12) ===");
        String targetPassword = "pass: Bereziuk";
        String sha256Hash5 = sha256(targetPassword);
        BCryptPasswordEncoder bcrypt12 = new BCryptPasswordEncoder(12);
        String bcryptHash6 = bcrypt12.encode(targetPassword);

        System.out.println("Хеш №5 (SHA-256): " + sha256Hash5);
        System.out.println("Хеш №6 (BCrypt cost=12): " + bcryptHash6);

        List<String> dictionary = new ArrayList<>();
        for (int i = 1; i <= 19; i++) dictionary.add("pass: candidate_" + i);
        dictionary.add(targetPassword);

        long startSha = System.nanoTime();
        for (String c : dictionary) {
            if (sha256(c).equals(sha256Hash5)) break;
        }
        System.out.printf("Перебір SHA-256 (20 кандидатів): %.3f мс%n", (System.nanoTime() - startSha) / 1_000_000.0);

        long startBcrypt = System.nanoTime();
        for (String c : dictionary) {
            if (bcrypt12.matches(c, bcryptHash6)) break;
        }
        double bcryptMs = (System.nanoTime() - startBcrypt) / 1_000_000.0;
        System.out.printf("Перебір BCrypt cost=12 (20 кандидатів): %.2f мс (%.2f с)%n", bcryptMs, bcryptMs / 1000.0);

        System.out.println("\n=== ЧАСТИНА 3. АВТЕНТИФІКАЦІЯ ТА АВТОРИЗАЦІЯ SAFEVAULT ===");
        AuthService auth = new AuthService();
        auth.register("oleksandr", "StrongPass2026!", "ROLE_ADMIN", "654321");
        auth.register("guest_user", "UserPass2026!", "ROLE_USER", null);

        String adminToken = auth.login("oleksandr", "StrongPass2026!", "654321");
        System.out.println("Вхід адміністратора успішний, sessionToken = " + adminToken);
        auth.authorize(adminToken, "ROLE_ADMIN");
        System.out.println("Доступ до адмін-функції дозволено (200 OK)");

        String userToken = auth.login("guest_user", "UserPass2026!", null);
        try {
            auth.authorize(userToken, "ROLE_ADMIN");
        } catch (SecurityException e) {
            System.out.println("Спроба звичайного користувача викликати адмін-метод -> " + e.getMessage());
        }

        auth.logout(adminToken);
        try {
            auth.authorize(adminToken, "ROLE_ADMIN");
        } catch (SecurityException e) {
            System.out.println("Запит після виходу з системи -> " + e.getMessage());
        }
    }

    private static String sha256(String input) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(hash);
    }

    private static String generateRandomString(int len) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        SecureRandom rnd = new SecureRandom();
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) sb.append(chars.charAt(rnd.nextInt(chars.length())));
        return sb.toString();
    }
}