import sys
import logging
from hackersec.analysis.rag import LocalRAGStore

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ─── OWASP Top 10 (2021) ────────────────────────────────────────────────────
OWASP_TOP_10 = [
    {
        "id": "A01:2021",
        "category": "OWASP Top 10",
        "text": "A01:2021 Broken Access Control. Access control enforces policy such that users cannot act outside their intended permissions. Failures lead to unauthorized information disclosure, modification, or destruction of data, or performing business functions outside the user's limits. Common vulnerabilities include: violation of least privilege, CORS misconfiguration, force browsing to authenticated pages as unauthenticated user, IDOR (Insecure Direct Object References), missing access control for POST/PUT/DELETE, elevation of privilege. Remediation: Deny by default except for public resources. Implement access control mechanisms once and reuse throughout the application. Disable web server directory listing and ensure file metadata and backup files are not present within web roots. Log access control failures and alert admins when appropriate."
    },
    {
        "id": "A02:2021",
        "category": "OWASP Top 10",
        "text": "A02:2021 Cryptographic Failures. Previously known as Sensitive Data Exposure. Failures related to cryptography which often lead to sensitive data exposure. Common vulnerabilities include: transmitting data in clear text (HTTP, SMTP, FTP), using old or weak cryptographic algorithms (MD5, SHA1, DES), using default or weak crypto keys, not enforcing encryption via security headers, improper certificate validation. Remediation: Classify data processed, stored, or transmitted. Identify which data is sensitive according to privacy laws and business needs. Apply controls per classification. Don't store sensitive data unnecessarily. Encrypt all sensitive data at rest and in transit using strong algorithms (AES-256, RSA-2048+). Use authenticated encryption. Store passwords using strong adaptive and salted hashing functions (bcrypt, scrypt, Argon2)."
    },
    {
        "id": "A03:2021",
        "category": "OWASP Top 10",
        "text": "A03:2021 Injection. An application is vulnerable to injection when: user-supplied data is not validated, filtered, or sanitized; dynamic queries or non-parameterized calls without context-aware escaping are used directly in the interpreter; hostile data is used within ORM search parameters to extract additional records; hostile data is directly used or concatenated to build SQL, OS commands, LDAP, XPath, or NoSQL queries. Common types: SQL injection (CWE-89), OS Command injection (CWE-78), LDAP injection (CWE-90), XPath injection. Remediation: Use a safe API which avoids using the interpreter entirely or provides a parameterized interface. Use positive server-side input validation. Escape special characters using interpreter-specific escape syntax. Use LIMIT and other SQL controls within queries to prevent mass disclosure in case of SQL injection."
    },
    {
        "id": "A04:2021",
        "category": "OWASP Top 10",
        "text": "A04:2021 Insecure Design. Insecure design focuses on risks related to design and architectural flaws, calling for more use of threat modeling, secure design patterns, and reference architectures. An insecure design cannot be fixed by a perfect implementation as by definition, needed security controls were never created to defend against specific attacks. Common issues: missing or ineffective control design, generating error messages containing sensitive information, credential stuffing due to lack of rate limiting. Remediation: Establish and use a secure development lifecycle. Use a library of secure design patterns or paved road components. Use threat modeling for critical authentication, access control, business logic, and key flows. Write unit and integration tests to validate all critical flows are resistant to the threat model."
    },
    {
        "id": "A05:2021",
        "category": "OWASP Top 10",
        "text": "A05:2021 Security Misconfiguration. The application might be vulnerable if: missing appropriate security hardening across any part of the application stack, improperly configured permissions on cloud services, unnecessary features are enabled or installed (ports, services, pages, accounts), default accounts and passwords are still enabled and unchanged, error handling reveals stack traces or overly informative error messages, latest security features are disabled or not configured securely, security settings in application servers, frameworks, libraries, databases not set to secure values. Remediation: A repeatable hardening process makes it fast and easy to deploy another environment that is appropriately locked down. Development, QA, and production environments should be configured identically with different credentials. Remove or do not install unused features and frameworks."
    },
    {
        "id": "A06:2021",
        "category": "OWASP Top 10",
        "text": "A06:2021 Vulnerable and Outdated Components. You are likely vulnerable if: you do not know the versions of all components you use (both client-side and server-side), the software is vulnerable, unsupported, or out of date, you do not scan for vulnerabilities regularly and subscribe to security bulletins, you do not fix or upgrade the underlying platform, frameworks, and dependencies in a risk-based, timely fashion, software developers do not test the compatibility of updated, upgraded, or patched libraries. Remediation: Remove unused dependencies, unnecessary features, components, files, documentation. Continuously inventory versions of both client-side and server-side components using tools like OWASP Dependency-Check, retire.js. Monitor for libraries and components that are unmaintained or do not create security patches for older versions."
    },
    {
        "id": "A07:2021",
        "category": "OWASP Top 10",
        "text": "A07:2021 Identification and Authentication Failures. Previously known as Broken Authentication. Confirmation of the user's identity, authentication, and session management is critical. Authentication weaknesses include: permitting automated attacks such as credential stuffing, permitting brute force, permitting default/weak/well-known passwords, using weak or ineffective credential recovery and forgot-password processes, using plain text/encrypted/weakly hashed password data stores, missing or ineffective multi-factor authentication, exposing session identifier in the URL, reusing session identifier after successful login. Remediation: Implement multi-factor authentication to prevent automated credential stuffing, brute force, and stolen credential reuse attacks. Do not deploy with any default credentials. Implement weak password checks. Use a server-side, secure, built-in session manager."
    },
    {
        "id": "A08:2021",
        "category": "OWASP Top 10",
        "text": "A08:2021 Software and Data Integrity Failures. Failures relate to code and infrastructure that does not protect against integrity violations. Examples include: using software from untrusted sources (plugins, libraries, modules) via untrusted repositories, insecure CI/CD pipelines introducing unauthorized access or malicious code, auto-update functionality where updates are downloaded without sufficient integrity verification, insecure deserialization where objects or data are encoded or serialized and are vulnerable to tampering. Remediation: Use digital signatures or similar mechanisms to verify the software or data is from the expected source and has not been altered. Ensure libraries and dependencies are consuming trusted repositories. Use a software supply chain security tool such as OWASP Dependency Check or OWASP CycloneDX. Ensure there is a review process for code and configuration changes."
    },
    {
        "id": "A09:2021",
        "category": "OWASP Top 10",
        "text": "A09:2021 Security Logging and Monitoring Failures. Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response occurs anytime: auditable events such as logins, failed logins, and high-value transactions are not logged, warnings and errors generate no/inadequate/unclear log messages, logs of applications and APIs are not monitored for suspicious activity, logs are only stored locally, appropriate alerting thresholds and response escalation processes are not in place or effective, penetration testing and DAST scans do not trigger alerts. Remediation: Ensure all login, access control, and server-side input validation failures can be logged with sufficient user context to identify suspicious or malicious accounts and held for sufficient time to allow delayed forensic analysis."
    },
    {
        "id": "A10:2021",
        "category": "OWASP Top 10",
        "text": "A10:2021 Server-Side Request Forgery (SSRF). SSRF flaws occur whenever a web application fetches a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall, VPN, or another type of network ACL. SSRF can be used to: scan internal networks, access internal services behind firewalls, read local files via file:// protocol, access cloud metadata services (169.254.169.254). Remediation: Sanitize and validate all client-supplied input data. Enforce URL schema, port, and destination with a positive allow list. Do not send raw responses to clients. Disable HTTP redirections."
    },
]

# ─── Top 25 Most Critical CWEs ──────────────────────────────────────────────
CWE_ENTRIES = [
    {
        "id": "CWE-89",
        "category": "CWE",
        "text": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection). The application constructs SQL queries using string concatenation with user-supplied input. An attacker can inject arbitrary SQL, bypassing authentication or extracting/modifying/deleting data. Affects confidentiality, integrity, and availability. CVSS: typically 9.8 (Critical). Remediation: Use parameterized queries (prepared statements) exclusively. Never concatenate user data into SQL strings. Use ORM methods that automatically parameterize. Apply least-privilege database permissions. Example fix: cursor.execute('SELECT * FROM users WHERE name = ?', (username,))."
    },
    {
        "id": "CWE-78",
        "category": "CWE",
        "text": "CWE-78: Improper Neutralization of Special Elements used in an OS Command (OS Command Injection). The application passes user input to a system shell (e.g., os.system(), subprocess with shell=True). Attackers inject shell metacharacters to execute arbitrary commands with the application's privileges. CVSS: typically 9.8 (Critical). Remediation: Avoid calling OS commands with user input entirely. If unavoidable, use subprocess with shell=False and pass arguments as a list. Validate input against a strict whitelist of allowed characters. Example fix: subprocess.run(['ping', '-c', '1', ip], shell=False)."
    },
    {
        "id": "CWE-79",
        "category": "CWE",
        "text": "CWE-79: Improper Neutralization of Input During Web Page Generation (Cross-site Scripting / XSS). The application includes untrusted data in web page output without proper encoding, allowing attackers to inject client-side scripts. Types: Reflected XSS (via URL parameters), Stored XSS (via database), DOM-based XSS (via client-side JavaScript). Impact: session hijacking, credential theft, defacement, malware distribution. Remediation: Encode all untrusted data before rendering in HTML context (use framework auto-escaping). Implement Content-Security-Policy headers. Use HttpOnly and Secure flags on session cookies."
    },
    {
        "id": "CWE-22",
        "category": "CWE",
        "text": "CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal). The application uses user input to construct file paths without sanitizing directory traversal sequences (../ or ..\\ on Windows). Attackers access files outside the intended directory, reading /etc/passwd, application source code, or configuration files. Remediation: Canonicalize the path using os.path.realpath() and verify it starts with the intended base directory. Use a whitelist of allowed filenames or directories. Never use raw user input in file path operations."
    },
    {
        "id": "CWE-20",
        "category": "CWE",
        "text": "CWE-20: Improper Input Validation. The application does not validate or incorrectly validates input that can affect control flow or data flow. This is a root cause for many other vulnerabilities including injection, buffer overflow, and path traversal. All externally-supplied data should be validated for type, length, range, format, and business rules before processing. Remediation: Use allowlist validation over denylist. Validate on the server side. Use strong typing. Validate all input at the point of entry. Centralize validation logic."
    },
    {
        "id": "CWE-287",
        "category": "CWE",
        "text": "CWE-287: Improper Authentication. The application does not sufficiently verify that a user is who they claim to be. Includes: missing authentication for critical functions, using single-factor when multi-factor is needed, weak password requirements, not invalidating sessions on logout/password change. Impact: unauthorized access to accounts, data, and administrative functions. Remediation: Implement multi-factor authentication. Use strong, adaptive password hashing (bcrypt, Argon2). Invalidate sessions properly. Protect against credential stuffing with rate limiting."
    },
    {
        "id": "CWE-862",
        "category": "CWE",
        "text": "CWE-862: Missing Authorization. The application does not perform authorization checks when a user attempts to access a resource or perform an action. Even if a user is authenticated, they may not be authorized to perform certain operations. This leads to horizontal and vertical privilege escalation. Remediation: Deny by default. Check authorization for every request. Use role-based access control (RBAC). Validate that the authenticated user owns or has permission to access the requested resource."
    },
    {
        "id": "CWE-798",
        "category": "CWE",
        "text": "CWE-798: Use of Hard-coded Credentials. The application contains hard-coded passwords, API keys, cryptographic keys, or other secrets in the source code. Anyone with access to the source code or binary can extract credentials. Secrets in version control persist in git history even after removal. Impact: unauthorized access to external services, databases, APIs. CVSS: typically 9.8 (Critical). Remediation: Store secrets in environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault). Never commit secrets to version control. Use .env files excluded via .gitignore. Rotate any credentials that were ever committed."
    },
    {
        "id": "CWE-502",
        "category": "CWE",
        "text": "CWE-502: Deserialization of Untrusted Data. The application deserializes data from untrusted sources (pickle.loads(), yaml.load(), Java ObjectInputStream) without validation. Attackers craft malicious serialized objects that execute arbitrary code upon deserialization. Impact: Remote Code Execution (RCE). CVSS: typically 9.8 (Critical). Remediation: Do not deserialize untrusted data. Use data-only formats like JSON instead of pickle/YAML. If deserialization is necessary, implement integrity checks (HMAC signatures). Use safe loaders (yaml.safe_load() instead of yaml.load())."
    },
    {
        "id": "CWE-918",
        "category": "CWE",
        "text": "CWE-918: Server-Side Request Forgery (SSRF). The application fetches resources from user-supplied URLs without validation. Attackers can probe internal networks, access cloud metadata endpoints (169.254.169.254), read local files (file://), or interact with internal services. Remediation: Validate and sanitize URLs. Use allowlists for permitted domains/IPs. Block requests to private IP ranges (10.x, 172.16-31.x, 192.168.x). Disable unnecessary URL schemes (file://, gopher://, dict://)."
    },
    {
        "id": "CWE-352",
        "category": "CWE",
        "text": "CWE-352: Cross-Site Request Forgery (CSRF). The web application does not verify that a request was intentionally sent by the authenticated user. Attackers trick users into performing unintended actions (transferring funds, changing passwords) by embedding malicious requests in images, iframes, or scripts on third-party sites. Remediation: Use anti-CSRF tokens (synchronizer token pattern). Verify Origin/Referer headers. Use SameSite cookie attribute. Require re-authentication for sensitive operations."
    },
    {
        "id": "CWE-434",
        "category": "CWE",
        "text": "CWE-434: Unrestricted Upload of File with Dangerous Type. The application allows file upload without restricting file types. Attackers upload executable files (web shells, scripts) that are then executed by the server. Impact: Remote Code Execution. Remediation: Validate file types by content (magic bytes), not just extension. Store uploads outside the web root. Use random filenames. Set proper Content-Type headers. Scan uploaded files for malware."
    },
    {
        "id": "CWE-611",
        "category": "CWE",
        "text": "CWE-611: Improper Restriction of XML External Entity Reference (XXE). The application parses XML input containing references to external entities. Attackers use XXE to read local files, perform SSRF, or cause denial of service. Libraries like Python's xml.etree.ElementTree, lxml, and Java's SAXParser are commonly affected. Remediation: Disable external entity processing and DTD processing in XML parsers. Use JSON instead of XML where possible. Use defusedxml library in Python."
    },
    {
        "id": "CWE-77",
        "category": "CWE",
        "text": "CWE-77: Improper Neutralization of Special Elements used in a Command (Command Injection). Generic form of command injection where the application constructs commands using unsanitized user input. Differs from CWE-78 (OS-specific) in that it covers any command interpreter. Includes template injection, expression language injection, and eval() injection. Remediation: Never pass user input to eval(), exec(), or any code interpreter. Use strict input validation. Prefer parameterized APIs."
    },
    {
        "id": "CWE-276",
        "category": "CWE",
        "text": "CWE-276: Incorrect Default Permissions. The application sets overly permissive file/directory permissions during installation or file creation. Sensitive files (config files, private keys, databases) become readable or writable by unauthorized users. Remediation: Apply least privilege. Set restrictive default permissions (0600 for sensitive files, 0700 for directories). Audit file permissions as part of deployment."
    },
    {
        "id": "CWE-190",
        "category": "CWE",
        "text": "CWE-190: Integer Overflow or Wraparound. An integer operation produces a value that exceeds the maximum for its type, wrapping around to a small or negative number. Can lead to buffer overflows, incorrect calculations, or bypassed security checks. Prevalent in C/C++ but also affects Python when interfacing with native code. Remediation: Validate integer inputs against expected ranges. Use safe integer arithmetic libraries. Check for overflow before performing operations."
    },
    {
        "id": "CWE-732",
        "category": "CWE",
        "text": "CWE-732: Incorrect Permission Assignment for Critical Resource. The application assigns incorrect permissions to a security-critical resource (database, config file, log file), potentially allowing unauthorized reading or modification. Remediation: Set restrictive permissions on all sensitive files and directories. Use chown/chmod appropriately. Implement file permission auditing in CI/CD pipelines."
    },
    {
        "id": "CWE-327",
        "category": "CWE",
        "text": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm. The application uses weak or broken cryptographic algorithms such as MD5, SHA1, DES, RC4, or ROT13. These algorithms have known weaknesses allowing collision attacks, brute-force attacks, or plaintext recovery. Remediation: Use AES-256-GCM for symmetric encryption, SHA-256 or SHA-3 for hashing, RSA-2048+ or ECDSA for asymmetric, bcrypt/Argon2/scrypt for password hashing. Never implement custom cryptography."
    },
    {
        "id": "CWE-259",
        "category": "CWE",
        "text": "CWE-259: Use of Hard-coded Password. The application contains a hard-coded password used for authentication or connecting to databases/APIs. Anyone with access to source code or decompiled binaries can extract the password. Remediation: Store passwords in environment variables, configuration files outside the repository, or dedicated secrets managers. Use .env files with .gitignore exclusion."
    },
    {
        "id": "CWE-94",
        "category": "CWE",
        "text": "CWE-94: Improper Control of Generation of Code (Code Injection / eval injection). The application dynamically evaluates code constructed from user input using eval(), exec(), compile(), or similar functions. Attackers inject arbitrary code that executes with the application's privileges, achieving full Remote Code Execution. CVSS: typically 9.8 (Critical). Remediation: Never use eval() or exec() with user-supplied input. Use ast.literal_eval() for safe evaluation of Python literals. Use sandboxed execution environments if dynamic evaluation is required."
    },
    {
        "id": "CWE-200",
        "category": "CWE",
        "text": "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor (Information Disclosure). The application exposes sensitive information such as: stack traces in error messages, database connection strings, internal IP addresses, user credentials, API keys in client-side code, verbose error pages in production. Remediation: Implement generic error pages for production. Log detailed errors server-side only. Review all API responses for data leakage. Never expose stack traces to end users."
    },
    {
        "id": "CWE-306",
        "category": "CWE",
        "text": "CWE-306: Missing Authentication for Critical Function. The application does not authenticate users before allowing access to critical functionality such as admin panels, data export, account deletion, or configuration changes. Attackers directly access privileged functions. Remediation: Require authentication for all non-public functionality. Implement authentication middleware that runs before request handlers. Use session-based or token-based authentication consistently."
    },
    {
        "id": "CWE-522",
        "category": "CWE",
        "text": "CWE-522: Insufficiently Protected Credentials. The application stores, transmits, or handles credentials insecurely: storing passwords in plaintext, logging credentials, transmitting over unencrypted channels, using reversible encryption instead of hashing. Remediation: Hash passwords using bcrypt, scrypt, or Argon2 with unique salts. Transmit credentials only over TLS. Never log credentials. Use credential managers."
    },
    {
        "id": "CWE-918",
        "category": "CWE",
        "text": "CWE-1321: Improperly Controlled Modification of Object Prototype Attributes (Prototype Pollution). In JavaScript applications, attackers modify the prototype of base objects by injecting properties through merge/clone operations with user input. This can lead to denial of service, property injection, and in some cases remote code execution. Remediation: Freeze prototypes using Object.freeze(Object.prototype). Validate JSON schema before merging. Use Map instead of plain objects for user-controlled keys."
    },
]

def main():
    logger.info("Initializing comprehensive RAG Knowledge Base with OWASP Top 10 + CWE data...")
    
    store = LocalRAGStore(data_dir="data")
    
    all_docs = OWASP_TOP_10 + CWE_ENTRIES
    
    # Always re-seed: delete old data if exists
    import os
    index_path = os.path.join("data", "kb.faiss")
    meta_path = os.path.join("data", "kb_meta.json")
    if os.path.exists(index_path):
        os.remove(index_path)
        logger.info("Removed old FAISS index.")
    if os.path.exists(meta_path):
        os.remove(meta_path)
        logger.info("Removed old metadata.")
    
    # Reinitialize store after deleting old data
    store = LocalRAGStore(data_dir="data")
    store.add_documents(all_docs)
    
    logger.info(f"Successfully seeded {len(all_docs)} entries into FAISS ({len(OWASP_TOP_10)} OWASP + {len(CWE_ENTRIES)} CWE).")
    logger.info(f"Index total vectors: {store.index.ntotal}")

if __name__ == "__main__":
    main()
