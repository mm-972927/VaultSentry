package com.vaultsentry;

import com.vaultsentry.handler.*;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;

/**
 * VaultSentry — Secret & Sensitive File Detection Engine
 *
 * Starts a pure Java HTTP server on port 8080.
 * No frameworks. No dependencies. Just Core Java.
 *
 * API:
 *   GET    /api/scans          → list all scans
 *   POST   /api/scans          → submit new scan
 *   GET    /api/scan/{id}      → get scan + findings
 *   DELETE /api/scan/{id}      → delete scan
 *   GET    /api/stats          → dashboard stats
 */
public class Main {

    private static final int PORT = 8080;

    public static void main(String[] args) throws IOException {

        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);

        server.createContext("/api/scans",  new ScansHandler());
        server.createContext("/api/scan/",  new ScanDetailHandler());
        server.createContext("/api/stats",  new StatsHandler());

        server.setExecutor(Executors.newCachedThreadPool());
        server.start();

        System.out.println();
        System.out.println("██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗");
        System.out.println("██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝");
        System.out.println("██║   ██║███████║██║   ██║██║     ██║   ");
        System.out.println("╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   ");
        System.out.println(" ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   ");
        System.out.println("  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   SENTRY");
        System.out.println();
        System.out.println("  Secret & Sensitive File Detection Engine");
        System.out.println("  ─────────────────────────────────────────");
        System.out.println("  Server  →  http://localhost:" + PORT);
        System.out.println("  Rules   →  12 content rules + 50 file pattern rules active");
        System.out.println();
        System.out.println("  Endpoints:");
        System.out.println("  GET  POST  /api/scans");
        System.out.println("  GET  DELETE /api/scan/{id}");
        System.out.println("  GET  /api/stats");
        System.out.println();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("[VaultSentry] Shutting down...");
            server.stop(2);
        }));
    }
}
