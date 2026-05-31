package com.vaultsentry.rules;

import com.vaultsentry.model.Finding;
import com.vaultsentry.model.Finding.Severity;
import com.vaultsentry.model.Finding.Category;

import java.util.*;

/**
 * SensitiveFileRule — detects dangerous/sensitive files by name or extension.
 *
 * Covers:
 *   1. Secret / credential files   (.env, .pem, .key, id_rsa …)
 *   2. Sourcemap files             (.js.map, .css.map)
 *   3. Build configuration files   (webpack.config.js, tsconfig.json, docker-compose.yml …)
 *   4. Log files                   (*.log, npm-debug.log, yarn-error.log …)
 *   5. OS artifact files           (.DS_Store, Thumbs.db, desktop.ini …)
 *
 * Demonstrates: Static initializer block, LinkedHashMap ordering,
 *               suffix matching, enum usage, static factory method
 */
public class SensitiveFileRule {

    // ── Internal risk descriptor ─────────────────────────────────────────────
    static class FileRisk {
        final Severity severity;
        final Category category;
        final String   description;
        final String   remediation;

        FileRisk(Severity severity, Category category, String description, String remediation) {
            this.severity    = severity;
            this.category    = category;
            this.description = description;
            this.remediation = remediation;
        }
    }

    // ── Master registry: filename / suffix  →  risk ──────────────────────────
    private static final Map<String, FileRisk> DANGEROUS_FILES = new LinkedHashMap<>();

    static {

        // ── 1. SOURCEMAP FILES ────────────────────────────────────────────────
        // Expose compiled frontend back to readable source in browser DevTools
        DANGEROUS_FILES.put(".js.map", new FileRisk(Severity.HIGH, Category.SENSITIVE_FILE,
            ".js.map sourcemap exposes your full JavaScript source in browser DevTools. " +
            "Attackers can reverse-engineer frontend logic, discover hidden API endpoints, and find embedded secrets.",
            "Configure Webpack/Vite to set 'devtool: false' in production. Add **/*.map to .gitignore. " +
            "Never deploy sourcemaps to a public-facing server."));

        DANGEROUS_FILES.put(".css.map", new FileRisk(Severity.MEDIUM, Category.SENSITIVE_FILE,
            "CSS sourcemap reveals original stylesheet structure and class naming conventions.",
            "Disable CSS sourcemap generation in production build config. Add *.css.map to .gitignore."));

        DANGEROUS_FILES.put(".ts.map", new FileRisk(Severity.HIGH, Category.SENSITIVE_FILE,
            "TypeScript sourcemap exposes original TypeScript source, revealing business logic.",
            "Set 'sourceMap: false' in tsconfig.json for production builds. Exclude from deployment."));

        // ── 2. ENVIRONMENT / SECRET FILES ─────────────────────────────────────
        DANGEROUS_FILES.put(".env", new FileRisk(Severity.CRITICAL, Category.SECRET_KEY,
            ".env file contains app secrets, DB credentials, and API keys in plaintext. " +
            "Anyone with repo access gains all these credentials.",
            "Add .env to .gitignore immediately. Provide a .env.example with placeholder values. " +
            "Use a secrets manager (HashiCorp Vault, AWS SSM) for real credentials."));

        DANGEROUS_FILES.put(".env.prod", new FileRisk(Severity.CRITICAL, Category.SECRET_KEY,
            "Production environment file with live credentials committed to source control.",
            "Remove immediately. Rotate all credentials. Never commit environment files."));

        DANGEROUS_FILES.put(".env.local", new FileRisk(Severity.HIGH, Category.SECRET_KEY,
            "Local environment file — may contain real DB or API credentials used in development.",
            "Add *.env.local to .gitignore. Share secrets securely via a team vault."));

        DANGEROUS_FILES.put(".env.staging", new FileRisk(Severity.HIGH, Category.SECRET_KEY,
            "Staging environment config may mirror production credentials.",
            "Never commit staging configs. Use CI/CD secret injection instead."));

        // ── 3. PRIVATE KEYS & CERTIFICATES ────────────────────────────────────
        DANGEROUS_FILES.put(".pem", new FileRisk(Severity.CRITICAL, Category.PRIVATE_KEY,
            "PEM file contains private key or certificate material. Leaking this compromises encryption.",
            "Remove from repo. Store in a key management service. Add *.pem to .gitignore."));

        DANGEROUS_FILES.put(".p12", new FileRisk(Severity.CRITICAL, Category.PRIVATE_KEY,
            "PKCS#12 keystore — bundles private key + certificate chain in one file.",
            "Remove immediately. Store keystores outside the project tree."));

        DANGEROUS_FILES.put(".key", new FileRisk(Severity.CRITICAL, Category.PRIVATE_KEY,
            "Raw private key file detected.",
            "Remove from repo. Add *.key to .gitignore. Rotate the key."));

        DANGEROUS_FILES.put(".jks", new FileRisk(Severity.HIGH, Category.PRIVATE_KEY,
            "Java KeyStore — may contain private keys used for TLS or code signing.",
            "Remove from source control. Pass keystore path via environment variable at runtime."));

        DANGEROUS_FILES.put("id_rsa", new FileRisk(Severity.CRITICAL, Category.PRIVATE_KEY,
            "SSH private key detected. Full server access is compromised if leaked.",
            "Revoke immediately at all servers. Generate a new keypair. Add id_rsa to .gitignore globally."));

        DANGEROUS_FILES.put("id_ed25519", new FileRisk(Severity.CRITICAL, Category.PRIVATE_KEY,
            "Ed25519 SSH private key — modern format but equally dangerous if exposed.",
            "Revoke and regenerate. Never store SSH keys in a repository."));

        // ── 4. SPRING BOOT / APPLICATION CONFIGS ─────────────────────────────
        DANGEROUS_FILES.put("application-prod.properties", new FileRisk(Severity.CRITICAL, Category.SECRET_KEY,
            "Production Spring Boot properties with live DB URLs, passwords, and secrets.",
            "Never commit prod configs. Use Spring Cloud Config Server or environment variable injection."));

        DANGEROUS_FILES.put("application-production.yml", new FileRisk(Severity.CRITICAL, Category.SECRET_KEY,
            "Production Spring Boot YAML config detected.",
            "Externalise all secrets. Use Kubernetes Secrets or a Vault sidecar in production."));

        DANGEROUS_FILES.put("credentials.json", new FileRisk(Severity.HIGH, Category.SECRET_KEY,
            "Credentials file — typically contains OAuth client secrets or service-account keys.",
            "Remove and rotate all credentials. Use secrets manager."));

        DANGEROUS_FILES.put("secrets.json", new FileRisk(Severity.HIGH, Category.SECRET_KEY,
            "Secrets file found in repository.",
            "Remove immediately. Store secrets in a vault, not in the codebase."));

        // ── 5. BUILD CONFIGURATION FILES ──────────────────────────────────────
        // These can expose internal infrastructure, ports, service names, env vars
        DANGEROUS_FILES.put("webpack.config.js", new FileRisk(Severity.MEDIUM, Category.SENSITIVE_FILE,
            "Webpack config may expose internal proxy targets, API base URLs, environment-specific settings, " +
            "and source map configuration that reveals build infrastructure.",
            "Audit for hardcoded URLs or tokens. Use environment variables for all dynamic values. " +
            "Keep production configs out of public repos."));

        DANGEROUS_FILES.put("webpack.config.prod.js", new FileRisk(Severity.HIGH, Category.SENSITIVE_FILE,
            "Production Webpack config — higher risk of embedded production endpoints or CDN tokens.",
            "Replace all hardcoded values with process.env references. Never commit API keys."));

        DANGEROUS_FILES.put("tsconfig.json", new FileRisk(Severity.LOW, Category.SENSITIVE_FILE,
            "TypeScript config reveals project structure, path aliases, and may expose internal module layout.",
            "Ensure no absolute server paths or credentials are embedded. " +
            "Restrict 'paths' aliases to relative project-internal routes."));

        DANGEROUS_FILES.put("tsconfig.prod.json", new FileRisk(Severity.MEDIUM, Category.SENSITIVE_FILE,
            "Production TypeScript config — may disable strict checks and reveal deploy-time settings.",
            "Review for any embedded URLs or env-specific values. Keep prod overrides minimal."));

        DANGEROUS_FILES.put("docker-compose.yml", new FileRisk(Severity.HIGH, Category.SENSITIVE_FILE,
            "Docker Compose file often contains hardcoded DB passwords, service credentials, " +
            "internal hostnames, and exposed ports that reveal full infrastructure topology.",
            "Replace all plaintext secrets with environment variable references (${VAR}). " +
            "Use Docker secrets for production. Never commit docker-compose.override.yml."));

        DANGEROUS_FILES.put("docker-compose.override.yml", new FileRisk(Severity.HIGH, Category.SENSITIVE_FILE,
            "Docker Compose override — frequently holds developer credentials or local secrets.",
            "Add docker-compose.override.yml to .gitignore. Use .env substitution instead."));

        DANGEROUS_FILES.put("docker-compose.prod.yml", new FileRisk(Severity.CRITICAL, Category.SENSITIVE_FILE,
            "Production Docker Compose config with live service credentials and infrastructure details.",
            "Never commit production compose files. Use Docker Swarm secrets or Kubernetes Secrets."));

        DANGEROUS_FILES.put(".dockerenv", new FileRisk(Severity.MEDIUM, Category.SENSITIVE_FILE,
            "Docker environment marker file — indicates container runtime secrets may be present.",
            "Audit the container for embedded secrets. Use Docker secrets management."));

        DANGEROUS_FILES.put("Dockerfile", new FileRisk(Severity.MEDIUM, Category.SENSITIVE_FILE,
            "Dockerfile may contain hardcoded ENV variables, credentials passed via ARG/ENV, " +
            "or internal base image registry URLs.",
            "Never use ARG/ENV for secrets in Dockerfiles — they persist in image layers. " +
            "Use multi-stage builds and runtime secret injection."));

        DANGEROUS_FILES.put(".babelrc", new FileRisk(Severity.LOW, Category.SENSITIVE_FILE,
            "Babel config reveals transpilation setup and plugin chain. " +
            "May expose internal transform logic or custom plugin paths.",
            "Keep generic. Avoid embedding environment-specific paths."));

        DANGEROUS_FILES.put("vite.config.js", new FileRisk(Severity.MEDIUM, Category.SENSITIVE_FILE,
            "Vite config can expose proxy targets, API base URLs, and server port configuration.",
            "Use import.meta.env for all dynamic values. Never hardcode backend URLs."));

        DANGEROUS_FILES.put("vite.config.ts", new FileRisk(Severity.MEDIUM, Category.SENSITIVE_FILE,
            "Vite TypeScript config — same risks as vite.config.js.",
            "Externalise all environment-specific values via .env files."));

        DANGEROUS_FILES.put("next.config.js", new FileRisk(Severity.MEDIUM, Category.SENSITIVE_FILE,
            "Next.js config may expose API rewrites, internal service URLs, and feature flags.",
            "Use process.env for all secrets. Review rewrites for internal service exposure."));

        DANGEROUS_FILES.put(".travis.yml", new FileRisk(Severity.HIGH, Category.SENSITIVE_FILE,
            "Travis CI config may contain encrypted secrets, deploy keys, or internal endpoint URLs. " +
            "Leaked deploy keys allow attackers to push malicious code.",
            "Use Travis CI encrypted environment variables. Rotate any exposed deploy keys immediately."));

        DANGEROUS_FILES.put(".gitlab-ci.yml", new FileRisk(Severity.HIGH, Category.SENSITIVE_FILE,
            "GitLab CI config may expose deployment targets, internal registry URLs, and runner secrets.",
            "Use GitLab CI/CD variables for all secrets. Never hardcode credentials in pipeline configs."));

        DANGEROUS_FILES.put("Jenkinsfile", new FileRisk(Severity.HIGH, Category.SENSITIVE_FILE,
            "Jenkins pipeline script may contain hardcoded credentials, internal server addresses, " +
            "or sensitive deployment logic.",
            "Use Jenkins Credentials Store. Reference via credentials() binding. " +
            "Never inline passwords or tokens."));

        DANGEROUS_FILES.put("buildspec.yml", new FileRisk(Severity.HIGH, Category.SENSITIVE_FILE,
            "AWS CodeBuild spec — may expose internal ECR registry paths, deployment targets, " +
            "or environment variable names hinting at secret structure.",
            "Use AWS Secrets Manager and Parameter Store. Reference via env/parameter-store in buildspec."));

        // ── 6. LOG FILES ────────────────────────────────────────────────────────
        // Logs often capture tokens, stack traces with internal paths, SQL queries with data
        DANGEROUS_FILES.put(".log", new FileRisk(Severity.MEDIUM, Category.SENSITIVE_FILE,
            "Log file may contain authentication tokens, session IDs, stack traces with internal " +
            "class paths, database queries, and accidentally logged passwords or API keys.",
            "Add *.log to .gitignore. Configure log frameworks to mask sensitive fields. " +
            "Never commit log files to version control."));

        DANGEROUS_FILES.put("npm-debug.log", new FileRisk(Severity.MEDIUM, Category.SENSITIVE_FILE,
            "NPM debug log reveals installed package tree, script commands, and may contain " +
            "environment variables captured during failed installs.",
            "Add npm-debug.log* to .gitignore. This file is auto-generated and must never be committed."));

        DANGEROUS_FILES.put("yarn-error.log", new FileRisk(Severity.MEDIUM, Category.SENSITIVE_FILE,
            "Yarn error log contains full install trace, dependency paths, and may expose " +
            "npm registry authentication tokens if a private registry was used.",
            "Add yarn-error.log to .gitignore. Rotate any npm/yarn auth tokens visible in the file."));

        DANGEROUS_FILES.put("yarn-debug.log", new FileRisk(Severity.LOW, Category.SENSITIVE_FILE,
            "Yarn debug log with build trace information.",
            "Add yarn-debug.log* to .gitignore."));

        DANGEROUS_FILES.put("pip-log.txt", new FileRisk(Severity.LOW, Category.SENSITIVE_FILE,
            "Python pip install log — may reveal internal PyPI mirror URLs or proxy settings.",
            "Add pip-log.txt to .gitignore."));

        DANGEROUS_FILES.put("hs_err_pid.log", new FileRisk(Severity.MEDIUM, Category.SENSITIVE_FILE,
            "JVM crash log — contains full heap dump references, internal memory addresses, " +
            "thread states, and JVM arguments that may include -D system properties with secrets.",
            "Add hs_err_pid*.log to .gitignore. Audit JVM startup args for embedded credentials."));

        // ── 7. OS ARTIFACT FILES ──────────────────────────────────────────────
        // No direct secret risk but indicate sloppy hygiene — red flag in code review
        DANGEROUS_FILES.put(".DS_Store", new FileRisk(Severity.LOW, Category.SENSITIVE_FILE,
            ".DS_Store is a macOS Finder metadata file that reveals the directory structure " +
            "of your project to anyone who receives it — exposing folder names, hidden directories, " +
            "and file organisation even if those files aren't in the repo.",
            "Add .DS_Store to global .gitignore (~/.gitignore_global). " +
            "Run: git rm --cached .DS_Store && echo .DS_Store >> .gitignore"));

        DANGEROUS_FILES.put("Thumbs.db", new FileRisk(Severity.LOW, Category.SENSITIVE_FILE,
            "Windows Explorer thumbnail cache — reveals image filenames and folder contents, " +
            "potentially exposing screenshots, internal diagrams, or confidential document names.",
            "Add Thumbs.db to .gitignore. Set Windows to not create thumbnail caches on network drives."));

        DANGEROUS_FILES.put("desktop.ini", new FileRisk(Severity.LOW, Category.SENSITIVE_FILE,
            "Windows folder customisation file — reveals internal folder structure and custom icon paths " +
            "that may hint at sensitive directory organisation.",
            "Add desktop.ini to .gitignore. This file is auto-generated by Windows."));

        DANGEROUS_FILES.put("ehthumbs.db", new FileRisk(Severity.LOW, Category.SENSITIVE_FILE,
            "Windows Media Center thumbnail database — may expose media file names.",
            "Add ehthumbs.db to .gitignore."));

        DANGEROUS_FILES.put(".spotlight-V100", new FileRisk(Severity.LOW, Category.SENSITIVE_FILE,
            "macOS Spotlight index directory — reveals filesystem metadata.",
            "Add .Spotlight-V100 to .gitignore."));

        DANGEROUS_FILES.put(".trashes", new FileRisk(Severity.LOW, Category.SENSITIVE_FILE,
            "macOS Trash metadata — may hint at recently deleted sensitive files.",
            "Add .Trashes to .gitignore."));

        DANGEROUS_FILES.put(".fseventsd", new FileRisk(Severity.LOW, Category.SENSITIVE_FILE,
            "macOS FSEvents directory — filesystem change journal.",
            "Add .fseventsd to .gitignore."));
    }

    /**
     * Check if a filename matches any dangerous pattern.
     * Returns a Finding if dangerous, null if clean.
     *
     * Matching strategy (in order):
     *   1. Exact name match          e.g. "Dockerfile", ".DS_Store"
     *   2. Suffix / extension match  e.g. anything ending in ".log", ".pem"
     */
    public static Finding check(String fileName, String filePath) {
        String lower = fileName.toLowerCase();

        for (Map.Entry<String, FileRisk> entry : DANGEROUS_FILES.entrySet()) {
            String pattern = entry.getKey();
            if (lower.equals(pattern) || lower.endsWith(pattern)) {
                FileRisk risk = entry.getValue();
                return new Finding(
                    "SENSITIVE_FILE",
                    "Sensitive File Detected: " + fileName,
                    risk.severity,
                    risk.category,
                    filePath,
                    0,
                    fileName,
                    risk.description,
                    risk.remediation
                );
            }
        }
        return null;
    }

    /** Returns all registered patterns — useful for a UI rules reference page */
    public static Set<String> getDangerousPatterns() {
        return Collections.unmodifiableSet(DANGEROUS_FILES.keySet());
    }

    /** Returns total number of registered file patterns */
    public static int getRuleCount() {
        return DANGEROUS_FILES.size();
    }
}
