package com.safevault.licensing;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public record LicensePayload(
        String licenseId,
        String productId,
        String licensee,
        Instant expiresAt,
        int maxDevices,
        List<String> features
) {
    public boolean hasFeature(String featureName) {
        return features != null && features.contains(featureName);
    }

    public static LicensePayload fromJson(String json) {
        String licenseId = extractString(json, "licenseId");
        String productId = extractString(json, "productId");
        String licensee = extractString(json, "licensee");
        String expiresAtRaw = extractString(json, "expiresAt");
        int maxDevices = extractInt(json, "maxDevices");
        List<String> features = extractArray(json, "features");

        return new LicensePayload(
                licenseId,
                productId,
                licensee,
                Instant.parse(expiresAtRaw),
                maxDevices,
                List.copyOf(features)
        );
    }

    private static String extractString(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]+)\"").matcher(json);
        if (!m.find()) {
            throw new SecurityException("Відсутнє обов'язкове поле ліцензії: " + key);
        }
        return m.group(1);
    }

    private static int extractInt(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*(\\d+)").matcher(json);
        if (!m.find()) {
            throw new SecurityException("Відсутнє числове поле ліцензії: " + key);
        }
        return Integer.parseInt(m.group(1));
    }

    private static List<String> extractArray(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\\[(.*?)]", Pattern.DOTALL).matcher(json);
        if (!m.find()) {
            throw new SecurityException("Відсутній масив функцій ліцензії: " + key);
        }
        List<String> items = new ArrayList<>();
        Matcher itemMatcher = Pattern.compile("\"([^\"]+)\"").matcher(m.group(1));
        while (itemMatcher.find()) {
            items.add(itemMatcher.group(1));
        }
        return items;
    }
}