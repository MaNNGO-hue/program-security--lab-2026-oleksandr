package com.safevault.network;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SafeVaultRestServer {
    private record StoredNote(String noteId, String ownerId, String content) {}

    private final HttpServer server;
    private final JwtTokenService tokenService = new JwtTokenService();

    private final Map<String, String> userPasswords = Map.of(
            "bereziuk", "S@feVault_02!",
            "ivanov", "Ivanov_Pass_99!"
    );
    private final Map<String, String> userRoles = Map.of(
            "bereziuk", "USER",
            "ivanov", "USER"
    );
    private final Map<String, StoredNote> notesDb = Map.of(
            "note-02", new StoredNote("note-02", "bereziuk", "API_SECRET_KEY=sfv_prod_bereziuk_02"),
            "note-99", new StoredNote("note-99", "ivanov", "PRIVATE_WALLET_SEED=ivanov_secret_99")
    );

    public SafeVaultRestServer() throws IOException {
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        registerRoutes();
    }

    public int getPort() {
        return server.getAddress().getPort();
    }

    public void start() {
        server.start();
    }

    public void stop() {
        server.stop(0);
    }

    private void registerRoutes() {
        server.createContext("/api/health", exchange -> {
            sendJson(exchange, 200, "{\"status\":\"UP\",\"service\":\"SafeVault-REST\"}");
        });

        server.createContext("/auth/login", exchange -> {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJson(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String username = extractField(body, "username");
            String password = extractField(body, "password");

            if (username == null || !userPasswords.containsKey(username) || !userPasswords.get(username).equals(password)) {
                sendJson(exchange, 401, "{\"error\":\"Invalid credentials\"}");
                return;
            }
            String role = userRoles.get(username);
            String access = tokenService.issueAccessToken(username, role, 900);
            String refresh = tokenService.issueRefreshToken(username, role);
            sendJson(exchange, 200, String.format(
                    "{\"access_token\":\"%s\",\"refresh_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":900}",
                    access, refresh
            ));
        });

        server.createContext("/auth/refresh", exchange -> {
            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                sendJson(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
                return;
            }
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String refresh = extractField(body, "refresh_token");
            try {
                Map.Entry<String, String> pair = tokenService.rotateTokens(refresh);
                sendJson(exchange, 200, String.format(
                        "{\"access_token\":\"%s\",\"refresh_token\":\"%s\",\"token_type\":\"Bearer\"}",
                        pair.getKey(), pair.getValue()
                ));
            } catch (SecurityException e) {
                sendJson(exchange, 401, "{\"error\":\"" + e.getMessage() + "\"}");
            }
        });

        server.createContext("/api/notes/", exchange -> {
            JwtTokenService.AuthenticatedPrincipal principal;
            try {
                principal = authenticateBearer(exchange);
            } catch (SecurityException e) {
                sendJson(exchange, 401, "{\"error\":\"" + e.getMessage() + "\"}");
                return;
            }

            String path = exchange.getRequestURI().getPath();
            String noteId = path.substring("/api/notes/".length());
            StoredNote note = notesDb.get(noteId);
            if (note == null) {
                sendJson(exchange, 404, "{\"error\":\"Note not found\"}");
                return;
            }

            if (!note.ownerId().equals(principal.userId()) && !"ADMIN".equals(principal.role())) {
                sendJson(exchange, 403, "{\"error\":\"403 Forbidden: Доступ заборонено! Нотатка належить іншому власнику.\"}");
                return;
            }

            sendJson(exchange, 200, String.format(
                    "{\"noteId\":\"%s\",\"owner\":\"%s\",\"content\":\"%s\"}",
                    note.noteId(), note.ownerId(), note.content()
            ));
        });

        server.createContext("/api/admin/audit", exchange -> {
            JwtTokenService.AuthenticatedPrincipal principal;
            try {
                principal = authenticateBearer(exchange);
            } catch (SecurityException e) {
                sendJson(exchange, 401, "{\"error\":\"" + e.getMessage() + "\"}");
                return;
            }

            if (!"ADMIN".equals(principal.role())) {
                sendJson(exchange, 403, "{\"error\":\"403 Forbidden: Потрібна роль ADMIN (поточна роль: " + principal.role() + ")\"}");
                return;
            }
            sendJson(exchange, 200, "{\"auditEvents\":42,\"status\":\"OK\"}");
        });
    }

    private JwtTokenService.AuthenticatedPrincipal authenticateBearer(HttpExchange exchange) {
        String authHeader = exchange.getRequestHeaders().getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new SecurityException("401 Unauthorized: Відсутній заголовок Authorization: Bearer <token>");
        }
        String rawToken = authHeader.substring("Bearer ".length()).trim();
        return tokenService.verifyAccessToken(rawToken);
    }

    private static void sendJson(HttpExchange exchange, int statusCode, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private static String extractField(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]+)\"").matcher(json);
        return m.find() ? m.group(1) : null;
    }
}