package com.vaultsentry.rules;

import com.vaultsentry.model.Finding;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * AbstractRegexRule — base class for all regex-powered detection rules.
 *
 * Demonstrates: Abstract class, Template Method Pattern, Regex (Pattern/Matcher)
 */
public abstract class AbstractRegexRule implements DetectionRule {

    protected final Pattern pattern;

    protected AbstractRegexRule(String regex) {
        // CASE_INSENSITIVE so we catch password=, PASSWORD=, Password= etc.
        this.pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
    }

    @Override
    public Finding scan(String line, int lineNumber, String filePath) {
        if (line == null || line.isBlank()) return null;

        // Skip comment lines (// or #) — reduce false positives
        String trimmed = line.trim();
        if (trimmed.startsWith("//") || trimmed.startsWith("#")
                || trimmed.startsWith("*") || trimmed.startsWith("/*")) {
            return null;
        }

        Matcher matcher = pattern.matcher(line);
        if (matcher.find()) {
            return buildFinding(line, lineNumber, filePath);
        }
        return null;
    }

    /** Subclasses construct the actual Finding with their metadata */
    protected abstract Finding buildFinding(String line, int lineNumber, String filePath);
}
