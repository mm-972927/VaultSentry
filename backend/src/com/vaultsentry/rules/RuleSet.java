package com.vaultsentry.rules;

import com.vaultsentry.model.Finding;
import com.vaultsentry.model.Finding.Severity;
import com.vaultsentry.model.Finding.Category;

/**
 * RuleSet — all concrete detection rules.
 *
 * Each inner class is one rule. Add new rules by extending AbstractRegexRule.
 * Demonstrates: Inner classes, Inheritance, Polymorphism, Regex patterns
 */
public class RuleSet {

    // ─────────────────────────────────────────────
    //  AWS
    // ─────────────────────────────────────────────

    public static class AwsAccessKeyRule extends AbstractRegexRule {
        public AwsAccessKeyRule() { super("(AKIA|AGPA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"); }

        @Override public String getRuleId()   { return "AWS_ACCESS_KEY"; }
        @Override public String getRuleName() { return "AWS Access Key ID"; }

        @Override
        protected Finding buildFinding(String line, int lineNumber, String filePath) {
            return new Finding(getRuleId(), getRuleName(), Severity.CRITICAL, Category.SECRET_KEY,
                filePath, lineNumber, line,
                "AWS Access Key ID detected. Exposes cloud infrastructure to unauthorized access.",
                "Rotate key immediately in AWS IAM. Use environment variables or AWS Secrets Manager.");
        }
    }

    public static class AwsSecretKeyRule extends AbstractRegexRule {
        public AwsSecretKeyRule() {
            super("aws.{0,20}(secret|key).{0,10}['\"]?[A-Za-z0-9/+=]{40}");
        }
        @Override public String getRuleId()   { return "AWS_SECRET_KEY"; }
        @Override public String getRuleName() { return "AWS Secret Access Key"; }

        @Override
        protected Finding buildFinding(String line, int lineNumber, String filePath) {
            return new Finding(getRuleId(), getRuleName(), Severity.CRITICAL, Category.SECRET_KEY,
                filePath, lineNumber, line,
                "AWS Secret Access Key detected. Full programmatic AWS access is compromised.",
                "Rotate in AWS IAM immediately. Never hardcode credentials — use IAM roles or Secrets Manager.");
        }
    }

    // ─────────────────────────────────────────────
    //  Passwords
    // ─────────────────────────────────────────────

    public static class HardcodedPasswordRule extends AbstractRegexRule {
        public HardcodedPasswordRule() {
            super("(password|passwd|pwd|secret)\\s*[=:]\\s*['\"]?[^\\s'\"]{6,}");
        }
        @Override public String getRuleId()   { return "HARDCODED_PASSWORD"; }
        @Override public String getRuleName() { return "Hardcoded Password"; }

        @Override
        protected Finding buildFinding(String line, int lineNumber, String filePath) {
            return new Finding(getRuleId(), getRuleName(), Severity.CRITICAL, Category.PASSWORD,
                filePath, lineNumber, line,
                "Hardcoded password found in source code. Anyone with repo access has this credential.",
                "Move to environment variables, a secrets vault (HashiCorp Vault, AWS SSM), or .env file excluded from Git.");
        }
    }

    public static class DatabaseUrlRule extends AbstractRegexRule {
        public DatabaseUrlRule() {
            super("(jdbc:|mongodb://|mysql://|postgres://).{0,80}(password|pwd)=[^\\s&\"']{3,}");
        }
        @Override public String getRuleId()   { return "DB_CONN_WITH_PASSWORD"; }
        @Override public String getRuleName() { return "Database URL with Password"; }

        @Override
        protected Finding buildFinding(String line, int lineNumber, String filePath) {
            return new Finding(getRuleId(), getRuleName(), Severity.CRITICAL, Category.DATABASE_URL,
                filePath, lineNumber, line,
                "Database connection string with embedded credentials found.",
                "Use connection pooling with externalized credentials. Never embed DB passwords in code.");
        }
    }

    // ─────────────────────────────────────────────
    //  Tokens
    // ─────────────────────────────────────────────

    public static class GitHubTokenRule extends AbstractRegexRule {
        public GitHubTokenRule() { super("gh[pousr]_[A-Za-z0-9_]{36,255}"); }
        @Override public String getRuleId()   { return "GITHUB_TOKEN"; }
        @Override public String getRuleName() { return "GitHub Personal Access Token"; }

        @Override
        protected Finding buildFinding(String line, int lineNumber, String filePath) {
            return new Finding(getRuleId(), getRuleName(), Severity.CRITICAL, Category.TOKEN,
                filePath, lineNumber, line,
                "GitHub PAT detected. Attacker can read/write all repos the token has access to.",
                "Revoke at github.com/settings/tokens. Use GitHub Actions secrets for CI/CD workflows.");
        }
    }

    public static class GenericApiKeyRule extends AbstractRegexRule {
        public GenericApiKeyRule() {
            super("(api_key|apikey|api-key)\\s*[=:]\\s*['\"]?[A-Za-z0-9\\-_]{20,}");
        }
        @Override public String getRuleId()   { return "GENERIC_API_KEY"; }
        @Override public String getRuleName() { return "Generic API Key"; }

        @Override
        protected Finding buildFinding(String line, int lineNumber, String filePath) {
            return new Finding(getRuleId(), getRuleName(), Severity.HIGH, Category.SECRET_KEY,
                filePath, lineNumber, line,
                "API key found in source. Could expose third-party services to abuse.",
                "Move to environment variables. Rotate the key with the service provider.");
        }
    }

    public static class StripeKeyRule extends AbstractRegexRule {
        public StripeKeyRule() { super("(sk|rk)_(live|test)_[A-Za-z0-9]{24,}"); }
        @Override public String getRuleId()   { return "STRIPE_SECRET_KEY"; }
        @Override public String getRuleName() { return "Stripe Secret Key"; }

        @Override
        protected Finding buildFinding(String line, int lineNumber, String filePath) {
            return new Finding(getRuleId(), getRuleName(), Severity.CRITICAL, Category.TOKEN,
                filePath, lineNumber, line,
                "Stripe secret key detected. Attacker can initiate charges and access customer data.",
                "Rotate immediately at dashboard.stripe.com. Use server-side env variables only.");
        }
    }

    public static class JwtSecretRule extends AbstractRegexRule {
        public JwtSecretRule() {
            super("(jwt.secret|jwt_secret|jwt-secret)\\s*[=:]\\s*['\"]?[^\\s'\"]{10,}");
        }
        @Override public String getRuleId()   { return "JWT_SECRET"; }
        @Override public String getRuleName() { return "JWT Secret Key"; }

        @Override
        protected Finding buildFinding(String line, int lineNumber, String filePath) {
            return new Finding(getRuleId(), getRuleName(), Severity.HIGH, Category.SECRET_KEY,
                filePath, lineNumber, line,
                "JWT signing secret exposed. Attacker can forge authentication tokens.",
                "Rotate secret and invalidate all existing tokens. Store in secrets manager.");
        }
    }

    // ─────────────────────────────────────────────
    //  Private Keys
    // ─────────────────────────────────────────────

    public static class PrivateKeyHeaderRule extends AbstractRegexRule {
        public PrivateKeyHeaderRule() {
            super("-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----");
        }
        @Override public String getRuleId()   { return "PRIVATE_KEY"; }
        @Override public String getRuleName() { return "Private Key / Certificate"; }

        @Override
        protected Finding buildFinding(String line, int lineNumber, String filePath) {
            return new Finding(getRuleId(), getRuleName(), Severity.CRITICAL, Category.PRIVATE_KEY,
                filePath, lineNumber, line,
                "Private key material embedded in source code. Compromises encryption and auth.",
                "Remove immediately. Store in secure key store. Add *.pem, *.key to .gitignore.");
        }
    }

    // ─────────────────────────────────────────────
    //  PII — India-specific
    // ─────────────────────────────────────────────

    public static class AadhaarRule extends AbstractRegexRule {
        // Aadhaar: 12-digit number, optionally space/hyphen separated in groups of 4
        public AadhaarRule() {
            super("\\b[2-9]{1}[0-9]{3}\\s?[0-9]{4}\\s?[0-9]{4}\\b");
        }
        @Override public String getRuleId()   { return "AADHAAR_NUMBER"; }
        @Override public String getRuleName() { return "Aadhaar Number (PII)"; }

        @Override
        protected Finding buildFinding(String line, int lineNumber, String filePath) {
            return new Finding(getRuleId(), getRuleName(), Severity.HIGH, Category.PII,
                filePath, lineNumber, line,
                "Possible Aadhaar number found. Storing/exposing Aadhaar violates DPDP Act 2023.",
                "Remove PII from source. Mask or tokenize before storing. Consult data privacy guidelines.");
        }
    }

    public static class PanCardRule extends AbstractRegexRule {
        public PanCardRule() { super("\\b[A-Z]{5}[0-9]{4}[A-Z]{1}\\b"); }
        @Override public String getRuleId()   { return "PAN_NUMBER"; }
        @Override public String getRuleName() { return "PAN Card Number (PII)"; }

        @Override
        protected Finding buildFinding(String line, int lineNumber, String filePath) {
            return new Finding(getRuleId(), getRuleName(), Severity.HIGH, Category.PII,
                filePath, lineNumber, line,
                "PAN card number pattern detected. Financial PII must not appear in source code.",
                "Remove PII. Use data masking in test environments. Never use real PII in dev/test.");
        }
    }

    public static class IndianPhoneRule extends AbstractRegexRule {
        public IndianPhoneRule() {
            super("(\\+91|0)?[6-9][0-9]{9}\\b");
        }
        @Override public String getRuleId()   { return "PHONE_NUMBER_IN"; }
        @Override public String getRuleName() { return "Indian Mobile Number (PII)"; }

        @Override
        protected Finding buildFinding(String line, int lineNumber, String filePath) {
            return new Finding(getRuleId(), getRuleName(), Severity.MEDIUM, Category.PII,
                filePath, lineNumber, line,
                "Indian phone number found in source. May indicate hardcoded test/prod PII.",
                "Replace with anonymized test data. Ensure no real user numbers in codebase.");
        }
    }
}
