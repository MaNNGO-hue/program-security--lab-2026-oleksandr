package com.safevault.network;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JwtTokenService {
    public record AuthenticatedPrincipal(String userId, String role, String tokenId) {}

    private record RefreshRecord(String userId, String role, boolean used) {}

    private final byte[] signingKey;
    private final SecureRandom secureRandom = new SecureRandom();
    private final Map<String, RefreshRecord> refreshStore = new ConcurrentHashMap<>();
    private final Set<String> revokedUsers = ConcurrentHashMap.newKeySet();

    public JwtTokenService() {
        this.signingKey = new byte[32];
        secureRandom.nextBytes(this.signingKey);
    }

    public String issueAccessToken(String userId, String role, long ttlSeconds) {
        long now = Instant.now().getEpochSecond();
        long exp = now + ttlSeconds;
        String jti = UUID.randomUUID().toString();

        String headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String payloadJson = String.format(
                "{\"sub\":\"%s\",\"role\":\"%s\",\"jti\":\"%s\",\"iat\":%d,\"exp\":%d}",
                userId, role, jti, now, exp
        );

        String encodedHeader = base64UrlEncode(headerJson.getBytes(StandardCharsets.UTF_8));
        String encodedPayload = base64UrlEncode(payloadJson.getBytes(StandardCharsets.UTF_8));
        String signingInput = encodedHeader + "." + encodedPayload;
        String signature = base64UrlEncode(hmacSha256(signingInput.getBytes(StandardCharsets.UTF_8)));

        return signingInput + "." + signature;
    }

    public AuthenticatedPrincipal verifyAccessToken(String token) {
        if (token == null || token.isBlank()) {
            throw new SecurityException("401 Unauthorized: Відсутній токен доступу Bearer");
        }
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw new SecurityException("401 Unauthorized: Некоректний формат JWT");
        }

        String signingInput = parts[0] + "." + parts[1];
        byte[] expectedSig = hmacSha256(signingInput.getBytes(StandardCharsets.UTF_8));
        byte[] actualSig;
        try {
            actualSig = Base64.getUrlDecoder().decode(parts[2]);
        } catch (IllegalArgumentException e) {
            throw new SecurityException("401 Unauthorized: Пошкоджений підпис JWT");
        }

        if (!MessageDigest.isEqual(expectedSig, actualSig)) {
            throw new SecurityException("401 Unauthorized: Недійсний криптографічний підпис JWT (виявлено підміну)!");
        }

        String header = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        if (!header.contains("\"alg\":\"HS256\"")) {
            throw new SecurityException("401 Unauthorized: Неприпустимий алгоритм підпису JWT");
        }

        String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        String sub = extractString(payload, "sub");
        String role = extractString(payload, "role");
        String jti = extractString(payload, "jti");
        long exp = extractLong(payload, "exp");

        if (Instant.now().getEpochSecond() >= exp) {
            throw new SecurityException("401 Unauthorized: Строк дії токена доступу вичерпано");
        }
        if (revokedUsers.contains(sub)) {
            throw new SecurityException("401 Unauthorized: Сесію користувача анульовано через компрометацію токена");
        }
        return new AuthenticatedPrincipal(sub, role, jti);
    }

    public String issueRefreshToken(String userId, String role) {
        byte[] rnd = new byte[24];
        secureRandom.nextBytes(rnd);
        String refreshToken = "rt_" + base64UrlEncode(rnd);
        refreshStore.put(refreshToken, new RefreshRecord(userId, role, false));
        return refreshToken;
    }

    public Map.Entry<String, String> rotateTokens(String refreshToken) {
        RefreshRecord record = refreshStore.get(refreshToken);
        if (record == null) {
            throw new SecurityException("401 Unauthorized: Невідомий refresh_token");
        }
        if (record.used()) {
            revokedUsers.add(record.userId());
            throw new SecurityException("401 Unauthorized: Повторне використання заміненого refresh_token! Усі сесії анульовано.");
        }
        refreshStore.put(refreshToken, new RefreshRecord(record.userId(), record.role(), true));
        String newAccess = issueAccessToken(record.userId(), record.role(), 900);
        String newRefresh = issueRefreshToken(record.userId(), record.role());
        return Map.entry(newAccess, newRefresh);
    }

    private byte[] hmacSha256(byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(signingKey, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Помилка обчислення підпису JWT", e);
        }
    }

    private static String base64UrlEncode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String extractString(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]+)\"").matcher(json);
        if (!m.find()) throw new SecurityException("401 Unauthorized: Відсутнє поле JWT: " + key);
        return m.group(1);
    }

    private static long extractLong(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*(\\d+)").matcher(json);
        if (!m.find()) throw new SecurityException("401 Unauthorized: Відсутнє числове поле JWT: " + key);
        return Long.parseLong(m.group(1));
    }
}