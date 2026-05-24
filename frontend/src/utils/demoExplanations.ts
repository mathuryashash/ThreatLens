export interface ExplanationData {
  explanation: string;
  mitre_tactic: string;
  recommended_actions: string[];
  cached: boolean;
}

const FALLBACK_EXPLANATIONS: Record<string, Omit<ExplanationData, "cached">> = {
  BRUTE_FORCE: {
    explanation: "A rapid series of failed password authentication attempts was detected from a single source IP address targeting the SSH service. This pattern is characteristic of an automated dictionary or brute force attack attempting to discover active login credentials to establish unauthorized access.",
    mitre_tactic: "Credential Access (TA0006)",
    recommended_actions: [
      "Add the offending IP address to the firewall blocklist or null-route it.",
      "Enforce key-based SSH authentication and disable password-based logins in sshd_config.",
      "Verify if any successful logins occurred from the same IP address around this time.",
      "Deploy fail2ban or a similar intrusion prevention daemon to automatically rate-limit future attempts."
    ]
  },
  SSH_BRUTE_FORCE: {
    explanation: "A rapid series of failed password authentication attempts was detected from a single source IP address targeting the SSH service. This pattern is characteristic of an automated dictionary or brute force attack attempting to discover active login credentials to establish unauthorized access.",
    mitre_tactic: "Credential Access (TA0006)",
    recommended_actions: [
      "Add the offending IP address to the firewall blocklist or null-route it.",
      "Enforce key-based SSH authentication and disable password-based logins in sshd_config.",
      "Verify if any successful logins occurred from the same IP address around this time.",
      "Deploy fail2ban or a similar intrusion prevention daemon to automatically rate-limit future attempts."
    ]
  },
  SQLI: {
    explanation: "The application intercepted HTTP requests containing common SQL database query syntax (e.g. 'UNION SELECT' or 'OR 1=1') within the query parameters. This indicates an attacker attempting to bypass authentication, expose system database schemas, or retrieve unauthorized table contents.",
    mitre_tactic: "Initial Access (TA0001)",
    recommended_actions: [
      "Ensure all database interactions utilize prepared statements and parameterized queries.",
      "Verify input sanitization rules on path and query parameters to strip SQL command keywords.",
      "Review application database connection permissions to ensure they follow the principle of least privilege.",
      "Audit web application logs to confirm the database returned error codes (400/500) rather than executing the payload."
    ]
  },
  SQL_INJECTION: {
    explanation: "The application intercepted HTTP requests containing common SQL database query syntax (e.g. 'UNION SELECT' or 'OR 1=1') within the query parameters. This indicates an attacker attempting to bypass authentication, expose system database schemas, or retrieve unauthorized table contents.",
    mitre_tactic: "Initial Access (TA0001)",
    recommended_actions: [
      "Ensure all database interactions utilize prepared statements and parameterized queries.",
      "Verify input sanitization rules on path and query parameters to strip SQL command keywords.",
      "Review application database connection permissions to ensure they follow the principle of least privilege.",
      "Audit web application logs to confirm the database returned error codes (400/500) rather than executing the payload."
    ]
  },
  SSRF: {
    explanation: "An HTTP request parameter contained web requests targeting private metadata IP endpoints (e.g. 169.254.169.254 or metadata.google.internal). This represents a Server-Side Request Forgery (SSRF) probe attempting to retrieve cloud provider security credentials or instance metadata.",
    mitre_tactic: "Discovery (TA0007)",
    recommended_actions: [
      "Implement strict allowlisting on any URL redirection or proxying parameters within the application.",
      "Block outbound traffic from the web server to the cloud metadata IP (169.254.169.254) at the cloud/network level.",
      "Audit access permissions on the instance service account role to restrict scope of potential leaked tokens."
    ]
  },
  SSRF_PROBE: {
    explanation: "An HTTP request parameter contained web requests targeting private metadata IP endpoints (e.g. 169.254.169.254 or metadata.google.internal). This represents a Server-Side Request Forgery (SSRF) probe attempting to retrieve cloud provider security credentials or instance metadata.",
    mitre_tactic: "Discovery (TA0007)",
    recommended_actions: [
      "Implement strict allowlisting on any URL redirection or proxying parameters within the application.",
      "Block outbound traffic from the web server to the cloud metadata IP (169.254.169.254) at the cloud/network level.",
      "Audit access permissions on the instance service account role to restrict scope of potential leaked tokens."
    ]
  },
  PATH_TRAVERSAL: {
    explanation: "The request URI or input parameter contains directory traversal sequences (like '../../' or '..\\'), indicating an attempt to traverse the server directory structure and read sensitive files outside the web document root (such as /etc/passwd).",
    mitre_tactic: "Discovery (TA0007)",
    recommended_actions: [
      "Sanitize all file paths using absolute/canonical path resolution and verify they remain within the target directory.",
      "Ensure the web server process runs under a low-privileged user account (e.g. www-data) with minimal read permissions.",
      "Utilize pre-defined index keys or database IDs to retrieve files rather than accepting arbitrary file path strings."
    ]
  },
  XSS: {
    explanation: "The request parameters contain HTML script tag elements, iframe definitions, or JavaScript event handlers (e.g. 'onerror', '<script>'). This suggests a Cross-Site Scripting (XSS) attack aiming to inject malicious code into the web application to execute within user browsers.",
    mitre_tactic: "Initial Access (TA0001)",
    recommended_actions: [
      "Apply strict context-aware output encoding on all user-supplied variables rendered in HTML views.",
      "Implement a robust Content Security Policy (CSP) header restricting script source locations and disabling inline scripts.",
      "Utilize modern frontend frameworks (like React/Next.js) which escape values automatically by default."
    ]
  },
  PRIV_ESC: {
    explanation: "Multiple failed root account password attempts or sudo command execution failures were logged for a user. This indicates an active privilege escalation attempt where a local/compromised user account is trying to gain administrative control.",
    mitre_tactic: "Privilege Escalation (TA0004)",
    recommended_actions: [
      "Audit user definitions in /etc/sudoers and restrict sudo access only to mandatory administrative users.",
      "Rotate the password for the involved user account and enforce strong password complexity policies.",
      "Verify if any successful root logins or sudo executions occurred from this account during the session."
    ]
  },
  PRIVILEGE_ESCALATION: {
    explanation: "Multiple failed root account password attempts or sudo command execution failures were logged for a user. This indicates an active privilege escalation attempt where a local/compromised user account is trying to gain administrative control.",
    mitre_tactic: "Privilege Escalation (TA0004)",
    recommended_actions: [
      "Audit user definitions in /etc/sudoers and restrict sudo access only to mandatory administrative users.",
      "Rotate the password for the involved user account and enforce strong password complexity policies.",
      "Verify if any successful root logins or sudo executions occurred from this account during the session."
    ]
  }
};

const GENERIC_FALLBACK: Omit<ExplanationData, "cached"> = {
  explanation: "A security event was logged matching potential attack signatures. Further analysis is recommended to investigate the event details, source IP activity, and target parameters.",
  mitre_tactic: "Initial Access (TA0001)",
  recommended_actions: [
    "Check raw log entries around the event timestamp to identify related scanning or probe patterns.",
    "Identify the source IP and verify if it has generated other security alerts.",
    "Review server and application access control policies for the affected endpoint."
  ]
};

export function getDemoExplanation(threatType: string): ExplanationData {
  const normalizedType = threatType.toUpperCase().replace(/\s+/g, "_");
  const base = FALLBACK_EXPLANATIONS[normalizedType] || GENERIC_FALLBACK;
  return {
    ...base,
    cached: true
  };
}
