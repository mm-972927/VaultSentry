package com.vaultsentry.util;

import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.io.OutputStream;

/**
 * HttpUtil — CORS headers, response helpers, JSON field parser.
 * Demonstrates: Static utility methods, encapsulation
 */
public class HttpUtil {

    public static void addCorsHeaders(HttpExchange exchange) {
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
        exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type");
        exchange.getResponseHeaders().add("Content-Type", "application/json");
    }

    public static void sendResponse(HttpExchange exchange, int statusCode, String jsonBody) throws IOException {
        byte[] bytes = jsonBody.getBytes("UTF-8");
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    public static void sendMethodNotAllowed(HttpExchange exchange) throws IOException {
        sendResponse(exchange, 405, "{\"error\":\"Method Not Allowed\"}");
    }

    public static void sendNotFound(HttpExchange exchange, String message) throws IOException {
        sendResponse(exchange, 404, "{\"error\":\"" + message + "\"}");
    }

    public static String readRequestBody(HttpExchange exchange) throws IOException {
        return new String(exchange.getRequestBody().readAllBytes(), "UTF-8");
    }

    public static String parseJsonField(String json, String key) {
        String search = "\"" + key + "\":\"";
        int start = json.indexOf(search);
        if (start == -1) return "";
        start += search.length();
        int end = json.indexOf("\"", start);
        return end == -1 ? "" : json.substring(start, end);
    }

    public static String buildStatsJson(java.util.Map<String, Object> map) {
        StringBuilder sb = new StringBuilder("{");
        int i = 0;
        for (java.util.Map.Entry<String, Object> e : map.entrySet()) {
            sb.append("\"").append(e.getKey()).append("\":");
            if (e.getValue() instanceof String) {
                sb.append("\"").append(e.getValue()).append("\"");
            } else {
                sb.append(e.getValue());
            }
            if (i++ < map.size() - 1) sb.append(",");
        }
        sb.append("}");
        return sb.toString();
    }
}
