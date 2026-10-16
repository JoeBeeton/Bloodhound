-- HTTP_TRACE_METHOD_ENABLED: closes a classic hardening-scanner gap (Nessus/Qualys/Nikto all
-- check this) that this product's HTTP_HEADERS module never had: whether the server processes
-- TRACE requests instead of rejecting them. RFC 7231 2.1 documents TRACE's own purpose as an
-- echo-the-request-back diagnostic loop-back - a server that answers it enables Cross-Site
-- Tracing (XST), letting a same-site XSS/CSRF primitive elsewhere read back an HttpOnly cookie's
-- value via the echoed request headers. MEDIUM: a real hardening gap and a well-established
-- scanner baseline, but most current browsers already block TRACE from fetch()/XHR, so the
-- practical exploitation path is narrower than it was when this check was first established.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('HTTP_TRACE_METHOD_ENABLED', 'HEADERS', 'MEDIUM',
 'HTTP TRACE method enabled',
 'The server processes HTTP TRACE requests instead of rejecting them (405/501), echoing the request back as the response body. This enables Cross-Site Tracing (XST): combined with a cross-site scripting or CSRF primitive elsewhere on the site, TRACE lets an attacker''s script read back a cookie''s value even when that cookie is marked HttpOnly, by echoing the request headers that carried it.',
 'Disable the TRACE (and TRACK, on IIS) HTTP method at the web server or reverse proxy level. On Apache, add "TraceEnable off"; on nginx, block the method explicitly (nginx has no native TRACE support, but a proxied/upstream backend can still echo it); on IIS, remove TRACE/TRACK via a URL Rewrite rule or the RequestFiltering verb denylist.',
 0.6);
