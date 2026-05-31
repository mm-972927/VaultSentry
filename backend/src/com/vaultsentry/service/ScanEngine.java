package com.vaultsentry.service;

import com.vaultsentry.model.Finding;
import com.vaultsentry.model.ScanResult;
import com.vaultsentry.rules.*;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;

/**
 * ScanEngine — walks a directory tree, applies all detection rules to each file.
 *
 * Demonstrates:
 *   - FileVisitor / Files.walkFileTree (recursive directory traversal)
 *   - List of interface implementations (Strategy Pattern)
 *   - BufferedReader for efficient line-by-line reading
 *   - Exception handling
 *   - Collections: List, Set
 */
public class ScanEngine {

    // All active regex-based content rules
    private final List<DetectionRule> contentRules;

    // File extensions we CAN scan for secret content (text-based)
    private static final Set<String> SCANNABLE_EXTENSIONS = new HashSet<>(Arrays.asList(
        // Source code
        ".java", ".js", ".ts", ".jsx", ".tsx", ".py", ".rb", ".go",
        ".cs", ".cpp", ".c", ".h", ".kt", ".scala", ".rs", ".swift", ".php",
        // Config & infra
        ".properties", ".yml", ".yaml", ".xml", ".json", ".env",
        ".config", ".conf", ".cfg", ".ini", ".toml", ".tf", ".tfvars",
        // Build & scripting
        ".sh", ".bat", ".gradle", ".md", ".html",
        // Log files — scan for accidentally logged tokens/passwords
        ".log"
    ));

    /**
     * Files that are flagged by NAME only (not content-scanned).
     * These are binary or metadata files — we detect them via SensitiveFileRule
     * but skip content scanning since they are not text-readable.
     */
    private static final Set<String> FILENAME_ONLY_CHECK = new HashSet<>(Arrays.asList(
        // OS artifacts
        ".ds_store", "thumbs.db", "desktop.ini", "ehthumbs.db",
        ".spotlight-v100", ".trashes", ".fseventsd",
        // Binary key/cert files
        ".p12", ".jks", ".pfx",
        // Sourcemaps (already caught but ensure no binary reads)
        ".js.map", ".css.map", ".ts.map"
    ));

    // Directories to always skip
    private static final Set<String> SKIP_DIRS = new HashSet<>(Arrays.asList(
        "node_modules", ".git", "target", "build", "dist", ".gradle",
        "__pycache__", ".idea", ".vscode", "vendor", "out", "bin", "coverage", "logs"
    ));

    public ScanEngine() {
        contentRules = new ArrayList<>();
        // Register all rules — adding a new rule is one line here
        contentRules.add(new RuleSet.AwsAccessKeyRule());
        contentRules.add(new RuleSet.AwsSecretKeyRule());
        contentRules.add(new RuleSet.HardcodedPasswordRule());
        contentRules.add(new RuleSet.DatabaseUrlRule());
        contentRules.add(new RuleSet.GitHubTokenRule());
        contentRules.add(new RuleSet.GenericApiKeyRule());
        contentRules.add(new RuleSet.StripeKeyRule());
        contentRules.add(new RuleSet.JwtSecretRule());
        contentRules.add(new RuleSet.PrivateKeyHeaderRule());
        contentRules.add(new RuleSet.AadhaarRule());
        contentRules.add(new RuleSet.PanCardRule());
        contentRules.add(new RuleSet.IndianPhoneRule());
    }

    /**
     * Entry point — runs the full scan on a given path.
     * The path can be a single file or a directory.
     */
    public void scan(ScanResult result, String targetPath) {
        result.setStatus(ScanResult.Status.SCANNING);
        Path root = Paths.get(targetPath);

        if (!Files.exists(root)) {
            result.markFailed("Path does not exist: " + targetPath);
            return;
        }

        try {
            if (Files.isRegularFile(root)) {
                scanFile(root, result);
            } else {
                Files.walkFileTree(root, new SecretFileVisitor(result, root));
            }
            result.markCompleted();
        } catch (IOException e) {
            result.markFailed("IO error during scan: " + e.getMessage());
        }
    }

    /**
     * Scans a single file — checks filename then scans content line by line.
     *
     * Decision flow:
     *   1. Always check filename against SensitiveFileRule (catches .DS_Store, Thumbs.db, .log etc.)
     *   2. If it's a filename-only type (binary/OS artifact) → skip content scan
     *   3. Otherwise scan line-by-line with all content rules
     */
    private void scanFile(Path file, ScanResult result) {
        String fileName = file.getFileName().toString();
        String relPath  = file.toString();

        // 1. Check if the filename itself is dangerous (applies to ALL files including OS artifacts)
        Finding fileFinding = SensitiveFileRule.check(fileName, relPath);
        if (fileFinding != null) {
            result.addFinding(fileFinding);
        }

        // 2. OS artifacts and binary files — filename check is enough, skip content scan
        String lowerName = fileName.toLowerCase();
        boolean isFilenameOnly = FILENAME_ONLY_CHECK.stream().anyMatch(lowerName::endsWith)
            || lowerName.equals(".ds_store")
            || lowerName.equals("thumbs.db")
            || lowerName.equals("desktop.ini");

        if (isFilenameOnly) {
            result.incrementSkipped();
            return;
        }

        // 3. Check if we can/should scan content
        if (!isScannableFile(fileName)) {
            result.incrementSkipped();
            return;
        }

        // 3. Scan content line by line
        try (BufferedReader reader = new BufferedReader(new FileReader(file.toFile()))) {
            String line;
            int lineNumber = 0;

            while ((line = reader.readLine()) != null) {
                lineNumber++;

                // Apply each rule to this line
                for (DetectionRule rule : contentRules) {
                    if (rule.appliesTo(fileName)) {
                        Finding finding = rule.scan(line, lineNumber, relPath);
                        if (finding != null) {
                            result.addFinding(finding);
                            break; // One finding per line — avoid duplicates from similar rules
                        }
                    }
                }
            }
            result.incrementScanned();

        } catch (IOException e) {
            // File may be binary or unreadable — skip it silently
            result.incrementSkipped();
        }
    }

    private boolean isScannableFile(String fileName) {
        String lower = fileName.toLowerCase();

        // Extension-based check
        for (String ext : SCANNABLE_EXTENSIONS) {
            if (lower.endsWith(ext)) return true;
        }

        // Exact filename matches — no extension but text-based
        Set<String> knownTextFiles = new HashSet<>(Arrays.asList(
            // Build / CI
            ".env", "makefile", "dockerfile", "jenkinsfile",
            "buildspec.yml", "procfile", "vagrantfile",
            // Build configs (may have no extension)
            "webpack.config.js", "webpack.config.prod.js",
            "vite.config.js", "vite.config.ts",
            "next.config.js", "babel.config.js", ".babelrc",
            "tsconfig.json", "tsconfig.prod.json",
            "docker-compose.yml", "docker-compose.override.yml",
            "docker-compose.prod.yml",
            ".travis.yml", ".gitlab-ci.yml",
            // Log files with specific names
            "npm-debug.log", "yarn-error.log", "yarn-debug.log",
            "pip-log.txt"
        ));
        return knownTextFiles.contains(lower);
    }

    /**
     * FileVisitor that walks directory tree, skipping build/vendor dirs.
     * Demonstrates: Anonymous class implementing FileVisitor interface
     */
    private class SecretFileVisitor extends SimpleFileVisitor<Path> {

        private final ScanResult result;
        private final Path root;

        SecretFileVisitor(ScanResult result, Path root) {
            this.result = result;
            this.root   = root;
        }

        @Override
        public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
            String dirName = dir.getFileName() != null ? dir.getFileName().toString() : "";
            if (SKIP_DIRS.contains(dirName) && !dir.equals(root)) {
                System.out.println("[SCAN] Skipping directory: " + dirName);
                return FileVisitResult.SKIP_SUBTREE;
            }
            return FileVisitResult.CONTINUE;
        }

        @Override
        public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
            // Skip very large files (> 2MB) — likely binary
            if (attrs.size() > 2 * 1024 * 1024) {
                result.incrementSkipped();
                return FileVisitResult.CONTINUE;
            }
            scanFile(file, result);
            return FileVisitResult.CONTINUE;
        }

        @Override
        public FileVisitResult visitFileFailed(Path file, IOException exc) {
            result.incrementSkipped();
            return FileVisitResult.CONTINUE;
        }
    }

    public int getRuleCount() {
        // Content rules + sensitive file patterns
        return contentRules.size() + SensitiveFileRule.getRuleCount();
    }
}
