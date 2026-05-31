package com.vaultsentry.rules;

import com.vaultsentry.model.Finding;
import java.util.List;

/**
 * DetectionRule — Strategy Pattern interface.
 * Every secret detection rule implements this.
 *
 * Demonstrates: Interface design, Strategy Pattern, Polymorphism
 */
public interface DetectionRule {

    /** Unique rule identifier e.g. "AWS_ACCESS_KEY" */
    String getRuleId();

    /** Human-readable name */
    String getRuleName();

    /**
     * Scan a single line of text from a file.
     * Returns a Finding if this rule matches, null otherwise.
     *
     * @param line       the raw text line
     * @param lineNumber 1-based line number
     * @param filePath   relative file path for the finding
     */
    Finding scan(String line, int lineNumber, String filePath);

    /**
     * Some rules apply only to specific file names (e.g. sourcemap rule).
     * Return true if this rule should be applied to the given filename.
     */
    default boolean appliesTo(String fileName) {
        return true;
    }
}
