-- Added by the rules audit. ZAP reports the cleartext-served case (10047 "HTTPS Content
-- Available via HTTP", 10106 "HTTP Only Site") but only at Tier 2 against authorized targets;
-- every Tier 1 HTTP_HEADERS run already talks to the host, so one extra plain-http GET with
-- no redirect following answers the question for every tracked target. MEDIUM when the site
-- serves content over cleartext, LOW when its first redirect hop is to another http:// URL -
-- see HttpHeaderParser#httpsRedirectFindings.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('HTTP_NO_HTTPS_REDIRECT', 'HEADERS', 'MEDIUM',
 'Plain HTTP not redirected to HTTPS',
 'The site answers on cleartext HTTP without redirecting to HTTPS. Anything a user or client sends before reaching the HTTPS version - and every visit that starts from an http:// link or a typed hostname - is readable and modifiable by anyone on the network path.',
 'Answer every plain-HTTP request with a 301 to the same path on https://, as the first hop, then enable HSTS (and preload) so browsers stop making the cleartext request at all.', 1.0);
