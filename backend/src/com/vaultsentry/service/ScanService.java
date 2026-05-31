package com.vaultsentry.service;

import com.vaultsentry.model.ScanResult;

import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

/**
 * ScanService — manages all scan jobs.
 *
 * Demonstrates:
 *   - Singleton pattern
 *   - ConcurrentHashMap for thread-safe storage
 *   - ExecutorService for async background scanning
 *   - Stream API for filtering and sorting
 *   - Generics: Map<String, ScanResult>
 */
public class ScanService {

    private static ScanService instance;

    private final Map<String, ScanResult> scanStore = new ConcurrentHashMap<>();
    private final ExecutorService executor = Executors.newFixedThreadPool(4);
    private final ScanEngine engine = new ScanEngine();

    private ScanService() {
        seedDemoScans();
    }

    public static synchronized ScanService getInstance() {
        if (instance == null) instance = new ScanService();
        return instance;
    }

    /**
     * Submits a new scan job — runs asynchronously in background thread
     */
    public ScanResult submitScan(String scanName, String targetPath, String requestedBy) {
        ScanResult result = new ScanResult(scanName, targetPath, requestedBy);
        scanStore.put(result.getId(), result);

        executor.submit(() -> {
            System.out.println("[SCAN] Starting: " + result.getId() + " → " + targetPath);
            engine.scan(result, targetPath);
            System.out.println("[SCAN] Done: " + result.getId()
                + " | Findings: " + result.getTotalFindings()
                + " | Risk: " + result.getRiskLevel());
        });

        return result;
    }

    /** Returns all scans sorted newest first */
    public List<ScanResult> getAllScans() {
        return scanStore.values().stream()
            .sorted(Comparator.comparing(ScanResult::getStartedAt).reversed())
            .collect(Collectors.toList());
    }

    public Optional<ScanResult> getScanById(String id) {
        return Optional.ofNullable(scanStore.get(id.toUpperCase()));
    }

    public boolean deleteScan(String id) {
        return scanStore.remove(id.toUpperCase()) != null;
    }

    /** Dashboard summary stats */
    public Map<String, Object> getStats() {
        List<ScanResult> all = new ArrayList<>(scanStore.values());
        long clean    = all.stream().filter(s -> "CLEAN".equals(s.getRiskLevel())).count();
        long critical = all.stream().filter(s -> "CRITICAL".equals(s.getRiskLevel())).count();
        long scanning = all.stream().filter(s -> s.getStatus() == ScanResult.Status.SCANNING).count();
        long totalFindings = all.stream().mapToLong(ScanResult::getTotalFindings).sum();

        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("totalScans",    all.size());
        stats.put("clean",         clean);
        stats.put("critical",      critical);
        stats.put("scanning",      scanning);
        stats.put("totalFindings", totalFindings);
        stats.put("rulesActive",   engine.getRuleCount());
        return stats;
    }

    /**
     * Seeds demo data by scanning the project's own source tree.
     * This way the app has real findings on first launch!
     */
    private void seedDemoScans() {
        // Scan a simulated vulnerable project path
        executor.submit(() -> {
            try { Thread.sleep(500); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            submitScan("demo-ecommerce-api",   "demo/ecommerce-api",   "system");
            submitScan("demo-auth-service",    "demo/auth-service",    "system");
        });
    }

    public void shutdown() { executor.shutdown(); }
}
