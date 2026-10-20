-- EXPOSURE_DOTNET_CONFIG_FILE: the .NET ecosystem's own equivalent of EXPOSURE_ENV_FILE - web.config
-- (classic .NET, XML) and appsettings.json (.NET Core, JSON) routinely hold connection strings and
-- API keys, the same secret-disclosure shape as a PHP/Node .env file. Properly-configured IIS
-- blocks web.config from being served as static content via a built-in handler mapping, but a
-- misconfigured reverse proxy/container setup serving a .NET app's whole publish directory as
-- static files has neither that protection nor PHP/Node's convention of treating a leading dot as
-- special. Matches on a real connectionString/ConnectionStrings element/key being present, not
-- just the file's own existence - the mere presence of a config file isn't itself the finding.
-- CRITICAL, same tier as EXPOSURE_ENV_FILE.
INSERT INTO rules_catalog (rule_id, category, default_severity, title, description, remediation_advice, weight) VALUES
('EXPOSURE_DOTNET_CONFIG_FILE', 'EXPOSURE', 'CRITICAL',
 '.NET configuration file exposed',
 'A .NET configuration file (web.config or appsettings.json) is publicly reachable and contains a connection string, routinely paired with database credentials, API keys, or other application secrets.',
 'Remove the config file from the publicly served directory, or explicitly block its extension/path at the web server or reverse proxy. Rotate any credentials that were exposed.',
 1.0);
