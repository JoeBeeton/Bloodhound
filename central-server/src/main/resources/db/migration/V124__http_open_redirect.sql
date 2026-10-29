-- Added by the rules audit's new-rule pass. HttpHeaderFetcher now sends one extra GET per common
-- redirect-param name (redirect/url/next/return/continue) carrying a fabricated, RFC 2606 .invalid
-- URL; if that exact marker reappears in a 3xx response's Location header, the server used the
-- param's value directly as a redirect destination with no allowlist check - see
-- HttpHeaderParser#openRedirectFindings for the full reasoning.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('HTTP_OPEN_REDIRECT', 'HEADERS', 'MEDIUM',
 'Open redirect via a request parameter',
 'A request parameter (e.g. redirect, url, next, return, continue) is used directly as the destination of an HTTP redirect, with no check that the value stays on this site. An attacker can craft a link that appears to point at this trusted domain but actually redirects the victim to an attacker-controlled site - commonly used to make phishing links or malware downloads look more credible.',
 'Validate any redirect-target parameter against an explicit allowlist of known-good paths/domains (or require a relative path only) before issuing a redirect - never pass an unvalidated parameter value straight into a Location header.', 0.6);
