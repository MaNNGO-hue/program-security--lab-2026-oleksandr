package com.safevault.network;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Lab10Runner {
    public static void main(String[] args) throws Exception {
        SafeVaultRestServer server = new SafeVaultRestServer();
        server.start();
        String baseUrl = "http://127.0.0.1:" + server.getPort();
        HttpClient client = HttpClient.newHttpClient();

        try {
            System.out.println("=== ЗАПУСК ЗАХИЩЕНОЇ КЛІЄНТ-СЕРВЕРНОЇ МОДЕЛІ SAFEVAULT (" + baseUrl + ") ===");

            // 1. Запит до захищеного маршруту без токена -> 401 Unauthorized
            HttpResponse<String> unauthResp = sendGet(client, baseUrl + "/api/notes/note-02", null, null);
            System.out.println("\n[1] Запит без Bearer-токена -> HTTP " + unauthResp.statusCode() + " | " + unauthResp.body());

            // 2. Мережева автентифікація користувача 'bereziuk' (варіант 02)
            String loginJson = "{\"username\":\"bereziuk\",\"password\":\"S@feVault_02!\"}";
            HttpResponse<String> loginResp = sendPost(client, baseUrl + "/auth/login", loginJson);
            String accessToken = extractJsonValue(loginResp.body(), "access_token");
            String refreshToken = extractJsonValue(loginResp.body(), "refresh_token");
            System.out.println("\n[2] Автентифікація (POST /auth/login) -> HTTP " + loginResp.statusCode());
            System.out.println("    Видано JWT Access Token:  " + accessToken.substring(0, 32) + "...");
            System.out.println("    Видано Refresh Token:     " + refreshToken);

            // 3. Доступ до власної нотатки з валідним Bearer JWT -> 200 OK
            HttpResponse<String> ownNoteResp = sendGet(client, baseUrl + "/api/notes/note-02", accessToken, null);
            System.out.println("\n[3] Читання власної нотатки (note-02) -> HTTP " + ownNoteResp.statusCode() + " | " + ownNoteResp.body());

            // 4. Спроба IDOR + підміна клієнтського заголовка X-Role: ADMIN -> 403 Forbidden
            HttpResponse<String> idorResp = sendGet(client, baseUrl + "/api/notes/note-99", accessToken, "ADMIN");
            System.out.println("\n[4] Спроба доступу до чужої нотатки (note-99) з підробленим X-Role: ADMIN -> HTTP "
                    + idorResp.statusCode() + " | " + idorResp.body());

            // 5. Спроба доступу звичайного USER до адмін-маршруту -> 403 Forbidden
            HttpResponse<String> adminResp = sendGet(client, baseUrl + "/api/admin/audit", accessToken, "ADMIN");
            System.out.println("\n[5] Спроба доступу до /api/admin/audit без ролі ADMIN -> HTTP "
                    + adminResp.statusCode() + " | " + adminResp.body());

            // 6. Спроба підміни payload у JWT (зміна ролі USER на ADMIN без перепідписання) -> 401 Unauthorized
            String[] jwtParts = accessToken.split("\\.");
            String forgedPayload = new String(Base64.getUrlDecoder().decode(jwtParts[1]), StandardCharsets.UTF_8)
                    .replace("\"role\":\"USER\"", "\"role\":\"ADMIN\"");
            String forgedJwt = jwtParts[0] + "."
                    + Base64.getUrlEncoder().withoutPadding().encodeToString(forgedPayload.getBytes(StandardCharsets.UTF_8))
                    + "." + jwtParts[2];
            HttpResponse<String> forgedResp = sendGet(client, baseUrl + "/api/admin/audit", forgedJwt, null);
            System.out.println("\n[6] Спроба використання модифікованого JWT -> HTTP "
                    + forgedResp.statusCode() + " | " + forgedResp.body());

            // 7. Одноразова ротація Refresh Token та блокування повторного використання
            HttpResponse<String> refresh1 = sendPost(client, baseUrl + "/auth/refresh",
                    "{\"refresh_token\":\"" + refreshToken + "\"}");
            System.out.println("\n[7] Планова ротація Refresh Token -> HTTP " + refresh1.statusCode());

            HttpResponse<String> replayResp = sendPost(client, baseUrl + "/auth/refresh",
                    "{\"refresh_token\":\"" + refreshToken + "\"}");
            System.out.println("    Повторне використання старого Refresh Token (Replay Attack) -> HTTP "
                    + replayResp.statusCode() + " | " + replayResp.body());
        } finally {
            server.stop();
        }
    }

    private static HttpResponse<String> sendGet(HttpClient client, String url, String bearerToken, String spoofedRoleHeader) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder().uri(URI.create(url)).GET();
        if (bearerToken != null) {
            builder.header("Authorization", "Bearer " + bearerToken);
        }
        if (spoofedRoleHeader != null) {
            builder.header("X-Role", spoofedRoleHeader);
        }
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> sendPost(HttpClient client, String url, String jsonBody) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static String extractJsonValue(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]+)\"").matcher(json);
        return m.find() ? m.group(1) : "";
    }
}