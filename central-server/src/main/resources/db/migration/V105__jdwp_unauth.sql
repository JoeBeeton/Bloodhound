-- EXPOSURE_JDWP_UNAUTH: the Java Debug Wire Protocol has no authentication concept at all by
-- protocol design - a reachable JDWP listener (started with e.g.
-- -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:8000 for remote debugging
-- convenience) lets anyone who can connect invoke arbitrary methods and inject arbitrary bytecode
-- into the running JVM - direct, unauthenticated remote code execution, with a well-known public
-- exploit module. Likely the most severe possible finding this product can produce, and it had no
-- coverage at all until now. Checked on both of JDWP's two conventional debug ports (5005 -
-- IntelliJ/Eclipse's own suggested default; 8000 - another extremely common convention), since
-- unlike Redis there's no single universal default. Confirmed via the protocol's own handshake: an
-- exact echo of the literal ASCII string "JDWP-Handshake" sent on connect - nothing else could
-- produce that exact response. CRITICAL.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_JDWP_UNAUTH', 'EXPOSURE', 'CRITICAL',
 'Java Debug Wire Protocol (JDWP) exposed',
 'A JDWP debug listener is reachable on one of its conventional debug ports (5005 or 8000). JDWP has no authentication concept at all by protocol design - anyone who can connect can invoke arbitrary methods and inject arbitrary bytecode into the running JVM, equivalent to direct, unauthenticated remote code execution. A well-known public exploit module targets exactly this.',
 'Never bind a JDWP listener to a publicly reachable address. If remote debugging is genuinely needed, bind to localhost only and tunnel over SSH, or restrict network access to trusted hosts.',
 1.0);
