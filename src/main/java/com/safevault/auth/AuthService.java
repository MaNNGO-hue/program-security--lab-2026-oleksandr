package com.safevault.auth;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class AuthService {
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder(12);
    private final Map<String, UserAccount> usersByUsername = new HashMap<>();
    private final Map<String, UserAccount> activeSessions = new HashMap<>();

    public UserAccount register(String username, String rawPassword, String role, String totpSecret) {
        if (usersByUsername.containsKey(username)) {
            throw new IllegalArgumentException("Користувач вже існує");
        }
        String hash = passwordEncoder.encode(rawPassword);
        UserAccount account = new UserAccount(username, hash, role, totpSecret);
        usersByUsername.put(username, account);
        return account;
    }

    public String login(String username, String rawPassword, String totpCode) {
        UserAccount user = usersByUsername.get(username);
        if (user == null || !passwordEncoder.matches(rawPassword, user.getPasswordHash())) {
            throw new SecurityException("401 Unauthorized: Невірний логін або пароль");
        }
        if (user.getTotpSecret() != null && !user.getTotpSecret().equals(totpCode)) {
            throw new SecurityException("401 Unauthorized: Невірний одноразовий код МФА");
        }
        String sessionToken = UUID.randomUUID().toString();
        activeSessions.put(sessionToken, user);
        return sessionToken;
    }

    public void authorize(String sessionToken, String requiredRole) {
        UserAccount user = activeSessions.get(sessionToken);
        if (user == null) {
            throw new SecurityException("401 Unauthorized: Сесія недійсна або завершена");
        }
        if (!user.getRole().equals(requiredRole)) {
            throw new SecurityException("403 Forbidden: Недостатньо прав доступу (" + requiredRole + ")");
        }
    }

    public void logout(String sessionToken) {
        activeSessions.remove(sessionToken);
    }
}