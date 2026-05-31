package com.vaultsentry.model;

/**
 * Finding — a single detected secret or sensitive item in a file.
 *
 * Demonstrates: Immutable design, Enum, Builder-style constructor
 */
public class Finding {

    public enum Severity {
        CRITICAL, HIGH, MEDIUM, LOW
    }

    public enum Category {
        SECRET_KEY,
        PASSWORD,
        PII,
        SENSITIVE_FILE,
        PRIVATE_KEY,
        TOKEN,
        DATABASE_URL
    }

    private final String ruleId;
    private final String ruleName;
    private final Severity severity;
    private final Category category;
    private final String filePath;
    private final int lineNumber;
    private final String matchedLine;   // redacted version shown to user
    private final String description;
    private final String remediation;

    public Finding(String ruleId, String ruleName, Severity severity, Category category,
                   String filePath, int lineNumber, String matchedLine,
                   String description, String remediation) {
        this.ruleId      = ruleId;
        this.ruleName    = ruleName;
        this.severity    = severity;
        this.category    = category;
        this.filePath    = filePath;
        this.lineNumber  = lineNumber;
        this.matchedLine = redact(matchedLine);
        this.description = description;
        this.remediation = remediation;
    }

    /**
     * Redacts sensitive portions — never expose actual secrets in output.
     * Demonstrates: String manipulation, regex-free masking
     */
    private String redact(String line) {
        if (line == null || line.length() <= 6) return "***REDACTED***";
        // Keep first 6 chars for context, mask the rest
        String trimmed = line.trim();
        if (trimmed.length() > 60) trimmed = trimmed.substring(0, 60) + "...";
        int maskFrom = Math.min(20, trimmed.length() / 2);
        return trimmed.substring(0, maskFrom) + "****REDACTED****";
    }

    public String getRuleId()      { return ruleId; }
    public String getRuleName()    { return ruleName; }
    public Severity getSeverity()  { return severity; }
    public Category getCategory()  { return category; }
    public String getFilePath()    { return filePath; }
    public int getLineNumber()     { return lineNumber; }
    public String getMatchedLine() { return matchedLine; }
    public String getDescription() { return description; }
    public String getRemediation() { return remediation; }

    public String toJson() {
        return "{"
            + "\"ruleId\":\""      + esc(ruleId)      + "\","
            + "\"ruleName\":\""    + esc(ruleName)    + "\","
            + "\"severity\":\""    + severity         + "\","
            + "\"category\":\""    + category         + "\","
            + "\"filePath\":\""    + esc(filePath)    + "\","
            + "\"lineNumber\":"    + lineNumber        + ","
            + "\"matchedLine\":\"" + esc(matchedLine) + "\","
            + "\"description\":\"" + esc(description) + "\","
            + "\"remediation\":\"" + esc(remediation) + "\""
            + "}";
    }

    private String esc(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "'");
    }
}
