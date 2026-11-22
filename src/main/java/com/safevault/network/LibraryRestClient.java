package com.safevault.network;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LibraryRestClient {
    private static final String BASE_URL = "http://127.0.0.1:8080";
    private static final String CLIENT_ID = "tulip-02";
    private static final String CLIENT_SECRET = "K3zN8tW5cY1s";

    public static void main(String[] args) throws Exception {
        HttpClient client = HttpClient.newHttpClient();

        // 1. Автоматична автентифікація (POST /auth/token)
        System.out.println("=== [1] АВТЕНТИФІКАЦІЯ КЛІЄНТА (POST /auth/token) ===");
        String authBody = String.format("{\"client_id\":\"%s\",\"client_secret\":\"%s\"}", CLIENT_ID, CLIENT_SECRET);
        HttpRequest authRequest = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/auth/token"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(authBody))
                .build();

        HttpResponse<String> authResponse = client.send(authRequest, HttpResponse.BodyHandlers.ofString());
        String accessToken = extractJsonValue(authResponse.body(), "access_token");
        System.out.println("HTTP " + authResponse.statusCode() + " | Отримано Bearer токен: " + accessToken);

        // 2. Запити до захищених маршрутів зі схемою Authorization: Bearer <token>
        System.out.println("\n=== [2] ДАНІ ПОТОЧНОГО ЧИТАЧА (GET /whoami) ===");
        System.out.println(sendAuthorizedGet(client, "/whoami", accessToken));

        System.out.println("\n=== [3] СПИСОК КНИГ (GET /api/books) ===");
        String booksJson = sendAuthorizedGet(client, "/api/books", accessToken);
        System.out.println(booksJson);

        String firstBookId = extractJsonValue(booksJson, "id");
        if (!firstBookId.isEmpty()) {
            System.out.println("\n=== [4] ДЕТАЛІ КНИГИ (GET /api/books/" + firstBookId + ") ===");
            System.out.println(sendAuthorizedGet(client, "/api/books/" + firstBookId, accessToken));
        }

        System.out.println("\n=== [5] АКТИВНІ ПОЗИКИ (GET /api/loans) ===");
        System.out.println(sendAuthorizedGet(client, "/api/loans", accessToken));

        System.out.println("\n=== [6] ЗВЕДЕНА ІНФОРМАЦІЯ (GET /api/summary) ===");
        System.out.println(sendAuthorizedGet(client, "/api/summary", accessToken));
    }

    private static String sendAuthorizedGet(HttpClient client, String path, String token) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + path))
                .header("Authorization", "Bearer " + token)
                .header("Accept", "application/json")
                .GET()
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString()).body();
    }

    private static String extractJsonValue(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]+)\"").matcher(json);
        return m.find() ? m.group(1) : "";
    }
}