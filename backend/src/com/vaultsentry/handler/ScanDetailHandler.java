package com.vaultsentry.handler;

import com.vaultsentry.model.ScanResult;
import com.vaultsentry.service.ScanService;
import com.vaultsentry.util.HttpUtil;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.util.Optional;

/**
 * ScanDetailHandler — handles /api/scan/{id}
 * GET    → fetch scan by ID with full findings
 * DELETE → remove a scan
 */
public class ScanDetailHandler implements HttpHandler {

    private final ScanService service = ScanService.getInstance();

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        HttpUtil.addCorsHeaders(exchange);
        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(204, -1);
            return;
        }

        String path = exchange.getRequestURI().getPath(); // /api/scan/{id}
        String[] parts = path.split("/");
        if (parts.length < 4) {
            HttpUtil.sendNotFound(exchange, "Scan ID not provided");
            return;
        }
        String scanId = parts[3].toUpperCase();

        switch (exchange.getRequestMethod()) {
            case "GET":    handleGet(exchange, scanId);    break;
            case "DELETE": handleDelete(exchange, scanId); break;
            default:       HttpUtil.sendMethodNotAllowed(exchange);
        }
    }

    private void handleGet(HttpExchange exchange, String id) throws IOException {
        Optional<ScanResult> scan = service.getScanById(id);
        if (scan.isPresent()) {
            HttpUtil.sendResponse(exchange, 200, scan.get().toJson());
        } else {
            HttpUtil.sendNotFound(exchange, "Scan not found: " + id);
        }
    }

    private void handleDelete(HttpExchange exchange, String id) throws IOException {
        boolean deleted = service.deleteScan(id);
        if (deleted) {
            HttpUtil.sendResponse(exchange, 200, "{\"message\":\"Scan " + id + " deleted\"}");
        } else {
            HttpUtil.sendNotFound(exchange, "Scan not found: " + id);
        }
    }
}
