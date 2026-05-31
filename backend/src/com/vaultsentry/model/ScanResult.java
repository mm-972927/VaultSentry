package com.vaultsentry.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * ScanResult — represents one full scan job with all its findings.
 *
 * Demonstrates: Collections, Generics, Enum, UUID, Stream-ready data
 */
public class ScanResult {

    public enum Status { QUEUED, SCANNING, COMPLETED, FAILED }

    private final String id;
    private final String targetPath;
    private final String scanName;
    private final String requestedBy;
    private Status status;
    private final LocalDateTime startedAt;
    private LocalDateTime completedAt;
    private final List<Finding> findings;
    private int filesScanned;
    private int filesSkipped;
    private String errorMessage;

    public ScanResult(String scanName, String targetPath, String requestedBy) {
        this.id           = generateId();
        this.scanName     = scanName;
        this.targetPath   = targetPath;
        this.requestedBy  = requestedBy;
        this.status       = Status.QUEUED;
        this.startedAt    = LocalDateTime.now();
        this.findings     = new ArrayList<>();
        this.filesScanned = 0;
        this.filesSkipped = 0;
    }

    private String generateId() {
        // Simple readable ID: VS-XXXXXXXX
        return "VS-" + Long.toHexString(System.currentTimeMillis()).toUpperCase().substring(4);
    }

    public void addFinding(Finding f)        { findings.add(f); }
    public void setStatus(Status s)          { this.status = s; }
    public void incrementScanned()           { filesScanned++; }
    public void incrementSkipped()           { filesSkipped++; }
    public void setErrorMessage(String msg)  { this.errorMessage = msg; }

    public void markCompleted() {
        this.status      = Status.COMPLETED;
        this.completedAt = LocalDateTime.now();
    }

    public void markFailed(String reason) {
        this.status       = Status.FAILED;
        this.completedAt  = LocalDateTime.now();
        this.errorMessage = reason;
    }

    /** Count findings by severity */
    public Map<String, Long> getSeverityCounts() {
        Map<String, Long> counts = new LinkedHashMap<>();
        counts.put("CRITICAL", findings.stream().filter(f -> f.getSeverity() == Finding.Severity.CRITICAL).count());
        counts.put("HIGH",     findings.stream().filter(f -> f.getSeverity() == Finding.Severity.HIGH).count());
        counts.put("MEDIUM",   findings.stream().filter(f -> f.getSeverity() == Finding.Severity.MEDIUM).count());
        counts.put("LOW",      findings.stream().filter(f -> f.getSeverity() == Finding.Severity.LOW).count());
        return counts;
    }

    /** Risk score: weighted sum of findings */
    public int getRiskScore() {
        Map<String, Long> c = getSeverityCounts();
        long score = c.get("CRITICAL") * 40 + c.get("HIGH") * 20
                   + c.get("MEDIUM") * 5  + c.get("LOW") * 1;
        return (int) Math.min(score, 100);
    }

    public String getRiskLevel() {
        int score = getRiskScore();
        if (score >= 70) return "CRITICAL";
        if (score >= 40) return "HIGH";
        if (score >= 15) return "MEDIUM";
        if (score > 0)   return "LOW";
        return "CLEAN";
    }

    public String getId()           { return id; }
    public String getScanName()     { return scanName; }
    public String getTargetPath()   { return targetPath; }
    public String getRequestedBy()  { return requestedBy; }
    public Status getStatus()       { return status; }
    public List<Finding> getFindings() { return Collections.unmodifiableList(findings); }
    public int getFilesScanned()    { return filesScanned; }
    public int getFilesSkipped()    { return filesSkipped; }
    public int getTotalFindings()   { return findings.size(); }

    public String getStartedAt() {
        return startedAt.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }
    public String getCompletedAt() {
        return completedAt == null ? "-"
             : completedAt.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }

    public String toJson() {
        Map<String, Long> sc = getSeverityCounts();
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"id\":\"").append(id).append("\",");
        sb.append("\"scanName\":\"").append(esc(scanName)).append("\",");
        sb.append("\"targetPath\":\"").append(esc(targetPath)).append("\",");
        sb.append("\"requestedBy\":\"").append(esc(requestedBy)).append("\",");
        sb.append("\"status\":\"").append(status).append("\",");
        sb.append("\"startedAt\":\"").append(getStartedAt()).append("\",");
        sb.append("\"completedAt\":\"").append(getCompletedAt()).append("\",");
        sb.append("\"filesScanned\":").append(filesScanned).append(",");
        sb.append("\"filesSkipped\":").append(filesSkipped).append(",");
        sb.append("\"totalFindings\":").append(findings.size()).append(",");
        sb.append("\"riskScore\":").append(getRiskScore()).append(",");
        sb.append("\"riskLevel\":\"").append(getRiskLevel()).append("\",");
        sb.append("\"severityCounts\":{");
        sb.append("\"CRITICAL\":").append(sc.get("CRITICAL")).append(",");
        sb.append("\"HIGH\":").append(sc.get("HIGH")).append(",");
        sb.append("\"MEDIUM\":").append(sc.get("MEDIUM")).append(",");
        sb.append("\"LOW\":").append(sc.get("LOW")).append("},");
        if (errorMessage != null) {
            sb.append("\"errorMessage\":\"").append(esc(errorMessage)).append("\",");
        }
        sb.append("\"findings\":[");
        for (int i = 0; i < findings.size(); i++) {
            sb.append(findings.get(i).toJson());
            if (i < findings.size() - 1) sb.append(",");
        }
        sb.append("]}");
        return sb.toString();
    }

    private String esc(String s) {
        return s == null ? "" : s.replace("\\", "/").replace("\"", "'");
    }
}
