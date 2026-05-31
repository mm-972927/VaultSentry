package com.vaultsentry.handler;

import com.vaultsentry.service.ScanService;
import com.vaultsentry.util.HttpUtil;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.util.Map;

/**
 * StatsHandler — GET /api/stats
 * Returns aggregated dashboard statistics
 */
public class StatsHandler implements HttpHandler {

    private final ScanService service = ScanService.getInstance();

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        HttpUtil.addCorsHeaders(exchange);
        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(204, -1);
            return;
        }
        if (!"GET".equals(exchange.getRequestMethod())) {
            HttpUtil.sendMethodNotAllowed(exchange);
            return;
        }
        Map<String, Object> stats = service.getStats();
        HttpUtil.sendResponse(exchange, 200, HttpUtil.buildStatsJson(stats));
    }
}
