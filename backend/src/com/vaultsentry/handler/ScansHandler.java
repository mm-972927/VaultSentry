package com.vaultsentry.handler;

import com.vaultsentry.model.ScanResult;
import com.vaultsentry.service.ScanService;
import com.vaultsentry.util.HttpUtil;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.util.List;

/**
 * ScansHandler — handles /api/scans
 * GET  → list all scan results
 * POST → submit a new scan job
 */
public class ScansHandler implements HttpHandler {

    private final ScanService service = ScanService.getInstance();

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        HttpUtil.addCorsHeaders(exchange);
        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(204, -1);
            return;
        }
        switch (exchange.getRequestMethod()) {
            case "GET":  handleGet(exchange);  break;
            case "POST": handlePost(exchange); break;
            default:     HttpUtil.sendMethodNotAllowed(exchange);
        }
    }

    private void handleGet(HttpExchange exchange) throws IOException {
        List<ScanResult> scans = service.getAllScans();
        StringBuilder json = new StringBuilder("[");
        for (int i = 0; i < scans.size(); i++) {
            json.append(scans.get(i).toJson());
            if (i < scans.size() - 1) json.append(",");
        }
        json.append("]");
        HttpUtil.sendResponse(exchange, 200, json.toString());
    }

    private void handlePost(HttpExchange exchange) throws IOException {
        String body       = HttpUtil.readRequestBody(exchange);
        String scanName   = HttpUtil.parseJsonField(body, "scanName");
        String targetPath = HttpUtil.parseJsonField(body, "targetPath");
        String requestedBy= HttpUtil.parseJsonField(body, "requestedBy");

        if (scanName.isEmpty() || targetPath.isEmpty() || requestedBy.isEmpty()) {
            HttpUtil.sendResponse(exchange, 400,
                "{\"error\":\"Required: scanName, targetPath, requestedBy\"}");
            return;
        }

        ScanResult result = service.submitScan(scanName, targetPath, requestedBy);
        HttpUtil.sendResponse(exchange, 201, result.toJson());
    }
}
