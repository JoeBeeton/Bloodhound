# Bloodhound Rules Catalog
Bloodhound currently ships **162 rules** across 10 categories. This document is generated directly from the live `rules_catalog` table (`central-server`'s database, populated by the Flyway migrations under `central-server/src/main/resources/db/migration/`) and reflects the catalog as of the date below - re-run the generation query after adding or changing rules to keep it current.

_Last regenerated: 2026-10-21._

## Summary

| Severity | Count |
|---|---|
| 🔴 CRITICAL | 48 |
| 🟠 HIGH | 39 |
| 🟡 MEDIUM | 39 |
| 🔵 LOW | 19 |
| ⚪ INFO | 17 |
| **Total** | **162** |

| Category | Count |
|---|---|
| [Exposure](#exposure) | 73 |
| [Network / Ports](#network--ports) | 11 |
| [DNS Posture](#dns-posture) | 24 |
| [TLS / HSTS](#tls--hsts) | 16 |
| [HTTP Headers](#http-headers) | 19 |
| [Subdomain Hygiene](#subdomain-hygiene) | 5 |
| [Brand / Typosquat](#brand--typosquat) | 4 |
| [WHOIS / Domain](#whois--domain) | 4 |
| [Breach Data](#breach-data) | 1 |
| [Compound Risk](#compound-risk) | 5 |

## Table of contents

- [Exposure](#exposure) (73)
- [Network / Ports](#network--ports) (11)
- [DNS Posture](#dns-posture) (24)
- [TLS / HSTS](#tls--hsts) (16)
- [HTTP Headers](#http-headers) (19)
- [Subdomain Hygiene](#subdomain-hygiene) (5)
- [Brand / Typosquat](#brand--typosquat) (4)
- [WHOIS / Domain](#whois--domain) (4)
- [Breach Data](#breach-data) (1)
- [Compound Risk](#compound-risk) (5)

## Exposure

| Rule ID | Severity | Title | Scope |
|---|---|---|---|
| `EXPOSURE_ACTUATOR_ENV` | 🔴 CRITICAL | Spring Boot Actuator environment endpoint exposed | Tier 1 + Tier 2 |
| `EXPOSURE_ACTUATOR_HEAPDUMP` | 🔴 CRITICAL | Spring Boot Actuator heap dump exposed | Tier 1 + Tier 2 |
| `EXPOSURE_AIRFLOW_UNAUTH` | 🔴 CRITICAL | Apache Airflow exposed without authentication | Tier 1 + Tier 2 |
| `EXPOSURE_AWS_CREDENTIALS` | 🔴 CRITICAL | Exposed AWS credentials file | Tier 1 + Tier 2 |
| `EXPOSURE_BACKUP_ARCHIVE` | 🔴 CRITICAL | Exposed backup archive | Tier 1 + Tier 2 |
| `EXPOSURE_CLOUD_BUCKET_BRUTEFORCE_DISCOVERED_PUBLIC` | 🔴 CRITICAL | Publicly listable cloud storage bucket (discovered via brand-name guessing) | Tier 2 (deep scan) only |
| `EXPOSURE_CLOUD_BUCKET_PUBLIC_LISTING` | 🔴 CRITICAL | Publicly listable cloud storage bucket | Tier 1 + Tier 2 |
| `EXPOSURE_COUCHDB_ADMIN_PARTY` | 🔴 CRITICAL | CouchDB reachable with no admin user configured ("admin party") | Tier 1 + Tier 2 |
| `EXPOSURE_DOCKER_API` | 🔴 CRITICAL | Docker Engine API exposed without authentication | Tier 1 + Tier 2 |
| `EXPOSURE_DOCKER_API_TLS` | 🔴 CRITICAL | Docker Engine API exposed on its TLS port without client verification | Tier 1 + Tier 2 |
| `EXPOSURE_DOTNET_CONFIG_FILE` | 🔴 CRITICAL | .NET configuration file exposed | Tier 1 + Tier 2 |
| `EXPOSURE_ELASTICSEARCH_UNAUTH` | 🔴 CRITICAL | Elasticsearch exposed without authentication | Tier 1 + Tier 2 |
| `EXPOSURE_ENV_FILE` | 🔴 CRITICAL | Exposed .env file | Tier 1 + Tier 2 |
| `EXPOSURE_ETCD_UNAUTH` | 🔴 CRITICAL | etcd exposed without authentication | Tier 1 + Tier 2 |
| `EXPOSURE_GIT_CONFIG` | 🔴 CRITICAL | Exposed .git/config | Tier 1 + Tier 2 |
| `EXPOSURE_JDWP_UNAUTH` | 🔴 CRITICAL | Java Debug Wire Protocol (JDWP) exposed | Tier 1 + Tier 2 |
| `EXPOSURE_JENKINS_SCRIPT` | 🔴 CRITICAL | Jenkins script console exposed | Tier 1 + Tier 2 |
| `EXPOSURE_JENKINS_SCRIPT_CONSOLE_UNAUTH` | 🔴 CRITICAL | Jenkins script console exposed without authentication | Tier 1 + Tier 2 |
| `EXPOSURE_JUPYTER_UNAUTH` | 🔴 CRITICAL | Jupyter Notebook exposed without authentication | Tier 1 + Tier 2 |
| `EXPOSURE_KUBECTL_PROXY_UNAUTH` | 🔴 CRITICAL | kubectl proxy exposed without authentication | Tier 1 + Tier 2 |
| `EXPOSURE_KUBERNETES_API_UNAUTH` | 🔴 CRITICAL | Kubernetes API server allows anonymous access | Tier 1 + Tier 2 |
| `EXPOSURE_LIVE_SECRET_DETECTED` | 🔴 CRITICAL | Live-looking secret found in exposed file | Tier 1 + Tier 2 |
| `EXPOSURE_MONGO_EXPRESS_UNAUTH` | 🔴 CRITICAL | Mongo Express exposed without authentication | Tier 1 + Tier 2 |
| `EXPOSURE_RABBITMQ_DEFAULT_CREDS` | 🔴 CRITICAL | RabbitMQ management API accepts default credentials | Tier 1 + Tier 2 |
| `EXPOSURE_REDIS_UNAUTH` | 🔴 CRITICAL | Redis exposed without authentication | Tier 1 + Tier 2 |
| `EXPOSURE_SOLR_ADMIN_UNAUTH` | 🔴 CRITICAL | Apache Solr admin API exposed without authentication | Tier 1 + Tier 2 |
| `EXPOSURE_SPRING_BOOT_H2_CONSOLE` | 🔴 CRITICAL | H2 database console exposed | Tier 1 + Tier 2 |
| `EXPOSURE_SQL_DUMP_FILE` | 🔴 CRITICAL | Exposed SQL database dump | Tier 1 + Tier 2 |
| `EXPOSURE_SSH_PRIVATE_KEY` | 🔴 CRITICAL | Exposed private key file | Tier 1 + Tier 2 |
| `EXPOSURE_SVN_ENTRIES` | 🔴 CRITICAL | Exposed .svn/entries | Tier 1 + Tier 2 |
| `EXPOSURE_VNC_NO_AUTH` | 🔴 CRITICAL | VNC reachable with no authentication required | Tier 1 + Tier 2 |
| `TECH_KNOWN_EXPLOITED_VULNERABILITY` | 🔴 CRITICAL | Actively exploited vulnerability in detected software | Tier 1 + Tier 2 |
| `EXPOSURE_ACTUATOR_BEANS` | 🟠 HIGH | Spring Boot Actuator beans endpoint exposed | Tier 1 + Tier 2 |
| `EXPOSURE_ACTUATOR_CONFIGPROPS` | 🟠 HIGH | Spring Boot Actuator configprops endpoint exposed | Tier 1 + Tier 2 |
| `EXPOSURE_ACTUATOR_INDEX` | 🟠 HIGH | Spring Boot Actuator index exposed | Tier 1 + Tier 2 |
| `EXPOSURE_ACTUATOR_LOGGERS` | 🟠 HIGH | Spring Boot Actuator loggers endpoint exposed | Tier 1 + Tier 2 |
| `EXPOSURE_ACTUATOR_MAPPINGS` | 🟠 HIGH | Spring Boot Actuator mappings endpoint exposed | Tier 1 + Tier 2 |
| `EXPOSURE_ACTUATOR_THREADDUMP` | 🟠 HIGH | Spring Boot Actuator thread dump endpoint exposed | Tier 1 + Tier 2 |
| `EXPOSURE_ADMINER` | 🟠 HIGH | Adminer database console exposed | Tier 1 + Tier 2 |
| `EXPOSURE_ASPNET_ELMAH` | 🟠 HIGH | ASP.NET ELMAH error log exposed | Tier 1 + Tier 2 |
| `EXPOSURE_ASPNET_TRACE_AXD` | 🟠 HIGH | ASP.NET trace.axd exposed | Tier 1 + Tier 2 |
| `EXPOSURE_CONSUL_UNAUTH` | 🟠 HIGH | Consul API exposed without authentication | Tier 1 + Tier 2 |
| `EXPOSURE_GRAFANA_UNAUTH` | 🟠 HIGH | Grafana exposed without authentication | Tier 1 + Tier 2 |
| `EXPOSURE_GRAPHQL_INTROSPECTION` | 🟠 HIGH | GraphQL introspection enabled | Tier 1 + Tier 2 |
| `EXPOSURE_KIBANA_UNAUTH` | 🟠 HIGH | Kibana console exposed without authentication | Tier 1 + Tier 2 |
| `EXPOSURE_LARAVEL_DEBUG_MODE` | 🟠 HIGH | Laravel debug mode enabled | Tier 1 + Tier 2 |
| `EXPOSURE_LARAVEL_TELESCOPE` | 🟠 HIGH | Laravel Telescope exposed | Tier 1 + Tier 2 |
| `EXPOSURE_MLFLOW_UNAUTH` | 🟠 HIGH | MLflow tracking server exposed without authentication | Tier 1 + Tier 2 |
| `EXPOSURE_PGADMIN` | 🟠 HIGH | pgAdmin console exposed | Tier 1 + Tier 2 |
| `EXPOSURE_PHPMYADMIN` | 🟠 HIGH | phpMyAdmin console exposed | Tier 1 + Tier 2 |
| `EXPOSURE_PHP_INFO` | 🟠 HIGH | phpinfo() page exposed | Tier 1 + Tier 2 |
| `EXPOSURE_PROMETHEUS_SERVER_UNAUTH` | 🟠 HIGH | Prometheus server exposed without authentication | Tier 1 + Tier 2 |
| `EXPOSURE_SNMP_DEFAULT_COMMUNITY` | 🟠 HIGH | SNMP accepts the default "public" community string | Tier 1 + Tier 2 |
| `EXPOSURE_TRAEFIK_DASHBOARD_UNAUTH` | 🟠 HIGH | Traefik dashboard exposed without authentication | Tier 1 + Tier 2 |
| `EXPOSURE_ACTUATOR_HEALTH_DETAILS` | 🟡 MEDIUM | Spring Boot Actuator health endpoint discloses internal system details | Tier 1 + Tier 2 |
| `EXPOSURE_APACHE_SERVER_STATUS` | 🟡 MEDIUM | Apache mod_status page exposed | Tier 1 + Tier 2 |
| `EXPOSURE_DIRECTORY_LISTING` | 🟡 MEDIUM | Directory listing enabled | Tier 1 + Tier 2 |
| `EXPOSURE_DOCUMENT_METADATA_PATH_LEAK` | 🟡 MEDIUM | Internal file path disclosed in document metadata | Tier 1 + Tier 2 |
| `EXPOSURE_DS_STORE` | 🟡 MEDIUM | Exposed .DS_Store file | Tier 1 + Tier 2 |
| `EXPOSURE_JS_SOURCE_MAP` | 🟡 MEDIUM | JavaScript source map exposed | Tier 1 + Tier 2 |
| `EXPOSURE_NGINX_STUB_STATUS` | 🟡 MEDIUM | nginx stub_status page exposed | Tier 1 + Tier 2 |
| `EXPOSURE_PROMETHEUS_METRICS` | 🟡 MEDIUM | Prometheus metrics endpoint exposed | Tier 1 + Tier 2 |
| `EXPOSURE_SWAGGER_UI` | 🟡 MEDIUM | Unauthenticated API schema exposed | Tier 1 + Tier 2 |
| `EXPOSURE_WORDPRESS_USER_ENUMERATION` | 🟡 MEDIUM | WordPress user enumeration via REST API | Tier 1 + Tier 2 |
| `EXPOSURE_WORDPRESS_XMLRPC` | 🟡 MEDIUM | WordPress xmlrpc.php enabled | Tier 1 + Tier 2 |
| `TECH_EOL_SOFTWARE_DETECTED` | 🟡 MEDIUM | End-of-life software detected | Tier 1 + Tier 2 |
| `TECH_KNOWN_CVE` | 🟡 MEDIUM | Known CVE in detected software version | Tier 1 + Tier 2 |
| `TECH_EOL_APPROACHING` | 🔵 LOW | Software approaching end-of-life | Tier 1 + Tier 2 |
| `EXPOSURE_ACTUATOR_HEALTH` | ⚪ INFO | Spring Boot Actuator health endpoint exposed | Tier 1 + Tier 2 |
| `EXPOSURE_ACTUATOR_INFO` | ⚪ INFO | Spring Boot Actuator info endpoint exposed | Tier 1 + Tier 2 |
| `EXPOSURE_DOCUMENT_METADATA_AUTHOR_INFO` | ⚪ INFO | Author/editor information disclosed in document metadata | Tier 1 + Tier 2 |
| `EXPOSURE_SECURITY_TXT_EXPIRED` | ⚪ INFO | security.txt has expired | Tier 1 + Tier 2 |
| `EXPOSURE_SECURITY_TXT_PRESENT` | ⚪ INFO | security.txt published | Tier 1 + Tier 2 |

### `EXPOSURE_ACTUATOR_ENV`

**Spring Boot Actuator environment endpoint exposed** — 🔴 CRITICAL

The /actuator/env endpoint is publicly reachable and discloses environment variables and configuration properties, often including credentials and API keys.

**Remediation:** Disable or authenticate the env actuator endpoint; never expose it on an unauthenticated public port.

### `EXPOSURE_ACTUATOR_HEAPDUMP`

**Spring Boot Actuator heap dump exposed** — 🔴 CRITICAL

The /actuator/heapdump endpoint is publicly reachable and returns a full JVM heap dump, which frequently contains credentials, session tokens, and other secrets held in memory.

**Remediation:** Disable or authenticate the heapdump actuator endpoint (management.endpoint.heapdump.enabled=false, or restrict actuator exposure to an internal network/authenticated management port).

### `EXPOSURE_AIRFLOW_UNAUTH`

**Apache Airflow exposed without authentication** — 🔴 CRITICAL

An Airflow webserver's REST API answered a real DAG list without authentication, disclosing every DAG's own Python source - which often embeds credentials or business logic - and, depending on the instance's role configuration, may also allow triggering DAG runs, i.e. arbitrary code execution on the Airflow host.

**Remediation:** Enable Airflow's authentication (RBAC) and ensure no anonymous/public role has been granted access, then restrict network access to the webserver to trusted hosts only.

### `EXPOSURE_AWS_CREDENTIALS`

**Exposed AWS credentials file** — 🔴 CRITICAL

A publicly readable .aws/credentials file was found, disclosing AWS access keys.

**Remediation:** Remove the credentials file from the web root immediately and rotate the exposed AWS keys.

### `EXPOSURE_BACKUP_ARCHIVE`

**Exposed backup archive** — 🔴 CRITICAL

A publicly readable backup archive (.zip/.tar.gz) was found at a commonly-guessed path, potentially containing the full site source, configuration, or a database export.

**Remediation:** Remove the archive from the publicly served directory, or move it behind authentication. Rotate any credentials it may have contained.

### `EXPOSURE_CLOUD_BUCKET_BRUTEFORCE_DISCOVERED_PUBLIC`

**Publicly listable cloud storage bucket (discovered via brand-name guessing)** — 🔴 CRITICAL

A cloud storage bucket whose name is related to this organization's brand - discovered by guessing common bucket-naming conventions against its root domain, not via any of the target's own DNS records - allows anyone to list its full contents without authentication. Because this bucket was found by name-guessing rather than a DNS reference the target actually controls, ownership should be confirmed before remediation (a similarly-named bucket can occasionally belong to an unrelated third party).

**Remediation:** If the bucket belongs to your organization: disable public directory listing (S3: remove public "List objects" grants/bucket policy; GCS: remove allUsers/allAuthenticatedUsers from the bucket's IAM policy; Azure: disable anonymous public access on the storage account/container; equivalent for DigitalOcean Spaces/Linode/Scaleway). If it does not belong to your organization, no action is needed - this is a coincidental name match.

### `EXPOSURE_CLOUD_BUCKET_PUBLIC_LISTING`

**Publicly listable cloud storage bucket** — 🔴 CRITICAL

A subdomain's DNS CNAME points directly at a cloud storage bucket (AWS S3 or Google Cloud Storage) that allows anyone to list its full contents, without any authentication.

**Remediation:** Disable public directory listing on the bucket (S3: remove public "List objects" grants/bucket policy; GCS: remove allUsers/allAuthenticatedUsers from the bucket's IAM policy). Individual objects may still need their own access review even after listing is disabled.

### `EXPOSURE_COUCHDB_ADMIN_PARTY`

**CouchDB reachable with no admin user configured ("admin party")** — 🔴 CRITICAL

A CouchDB instance answered /_all_dbs without authentication, listing every database on the server. This is CouchDB's historical "admin party" mode (no admin user configured at all, the pre-2.0 default) - with no admin user set, read and write access to every database is open to anyone who connects.

**Remediation:** Create an admin user immediately (CouchDB's setup wizard or the _node config API), which disables admin-party mode and requires authentication for all database access.

### `EXPOSURE_DOCKER_API`

**Docker Engine API exposed without authentication** — 🔴 CRITICAL

The Docker Engine remote API is reachable on the network without TLS/authentication, allowing full control of containers on the host - equivalent to root access.

**Remediation:** Never expose the Docker daemon socket over plain TCP; if remote access is required, use TLS client-certificate authentication and firewall the port.

### `EXPOSURE_DOCKER_API_TLS`

**Docker Engine API exposed on its TLS port without client verification** — 🔴 CRITICAL

The Docker Engine remote API is reachable on its TLS-secured port (2376), but without requiring a trusted client certificate - a documented misconfiguration (--tls set without --tlsverify, or a server cert issued with no client-CA check) that leaves the full API open to anyone who can complete a TLS handshake. Equivalent to root access on the host.

**Remediation:** Enable --tlsverify (not just --tls) so the daemon requires and validates a client certificate signed by your own CA, or firewall this port to trusted hosts only.

### `EXPOSURE_DOTNET_CONFIG_FILE`

**.NET configuration file exposed** — 🔴 CRITICAL

A .NET configuration file (web.config or appsettings.json) is publicly reachable and contains a connection string, routinely paired with database credentials, API keys, or other application secrets.

**Remediation:** Remove the config file from the publicly served directory, or explicitly block its extension/path at the web server or reverse proxy. Rotate any credentials that were exposed.

### `EXPOSURE_ELASTICSEARCH_UNAUTH`

**Elasticsearch exposed without authentication** — 🔴 CRITICAL

An Elasticsearch HTTP API is reachable without authentication, allowing full read (and often write/delete) access to all indexed data.

**Remediation:** Enable Elasticsearch security features (authentication/TLS) and restrict network access to the cluster.

### `EXPOSURE_ENV_FILE`

**Exposed .env file** — 🔴 CRITICAL

A publicly readable .env file was found containing environment-variable-style entries, commonly including database credentials, API keys, or application secrets.

**Remediation:** Remove .env from the web root and ensure environment files are never deployed into a publicly served directory.

### `EXPOSURE_ETCD_UNAUTH`

**etcd exposed without authentication** — 🔴 CRITICAL

An etcd instance's v3 KV API is reachable on its default port (2379) without authentication, allowing a full read of every key in the store. etcd commonly backs Kubernetes' entire cluster state, including Secrets, which (absent an explicit encryption-at-rest configuration) are stored base64-encoded rather than truly encrypted - making an exposed, unauthenticated etcd close to a full cluster compromise, not just a data-disclosure finding.

**Remediation:** Enable etcd client-certificate authentication (--client-cert-auth) and restrict network access to the cluster's own control-plane nodes only. Never expose etcd's client port to the internet.

### `EXPOSURE_GIT_CONFIG`

**Exposed .git/config** — 🔴 CRITICAL

The .git/config file is publicly readable, and often the rest of the .git directory can be used to reconstruct the full source repository, including any secrets ever committed.

**Remediation:** Remove .git from the web root, or block access to dotfiles at the web server/proxy layer.

### `EXPOSURE_JDWP_UNAUTH`

**Java Debug Wire Protocol (JDWP) exposed** — 🔴 CRITICAL

A JDWP debug listener is reachable on one of its conventional debug ports (5005 or 8000). JDWP has no authentication concept at all by protocol design - anyone who can connect can invoke arbitrary methods and inject arbitrary bytecode into the running JVM, equivalent to direct, unauthenticated remote code execution. A well-known public exploit module targets exactly this.

**Remediation:** Never bind a JDWP listener to a publicly reachable address. If remote debugging is genuinely needed, bind to localhost only and tunnel over SSH, or restrict network access to trusted hosts.

### `EXPOSURE_JENKINS_SCRIPT`

**Jenkins script console exposed** — 🔴 CRITICAL

The Jenkins Groovy script console is publicly reachable without authentication, which allows arbitrary code execution on the Jenkins host.

**Remediation:** Require authentication for all Jenkins endpoints immediately; treat this as an active compromise risk.

### `EXPOSURE_JENKINS_SCRIPT_CONSOLE_UNAUTH`

**Jenkins script console exposed without authentication** — 🔴 CRITICAL

Jenkins's Groovy script console is publicly reachable without authentication, allowing arbitrary Groovy code execution - equivalent to full remote code execution on the Jenkins host.

**Remediation:** Enable Jenkins's security realm and authorization strategy so the script console requires an authenticated administrator, and firewall the Jenkins port to trusted hosts only.

### `EXPOSURE_JUPYTER_UNAUTH`

**Jupyter Notebook exposed without authentication** — 🔴 CRITICAL

A Jupyter Notebook instance on its default port (8888) answered its API without requiring a token or password, confirmed via a real /api/status response. Jupyter's notebook cells execute arbitrary code - unauthenticated access is equivalent to direct remote code execution on the host.

**Remediation:** Set a token or password immediately (Jupyter generates one by default; never run with --NotebookApp.token='' or --NotebookApp.password='' on a publicly reachable host), and restrict network access to trusted hosts only.

### `EXPOSURE_KUBECTL_PROXY_UNAUTH`

**kubectl proxy exposed without authentication** — 🔴 CRITICAL

A kubectl proxy instance is publicly reachable on its default port (8001) and answers an authenticated endpoint (/api/v1/namespaces) without credentials, disclosing the cluster's real namespace list. kubectl proxy is meant for local development convenience and is normally bound to localhost - Kubernetes' own hardening documentation specifically warns against running it with a public bind address, and real-world incidents (including the 2018 Tesla cryptojacking breach) trace back to exactly this misconfiguration.

**Remediation:** Stop running kubectl proxy with a public bind address (--address=0.0.0.0). If remote API access is genuinely needed, use a properly authenticated and TLS-protected path instead (e.g. the apiserver directly with client certificates, or a VPN/bastion).

### `EXPOSURE_KUBERNETES_API_UNAUTH`

**Kubernetes API server allows anonymous access** — 🔴 CRITICAL

The Kubernetes API server is reachable on its standard port (6443) and answers an authenticated endpoint (/api/v1/namespaces) without credentials, disclosing the cluster's real namespace list. Anonymous read access to cluster-management data is often a foothold for broader cluster compromise - this is the control plane itself, not just an application.

**Remediation:** Disable anonymous authentication on the API server (--anonymous-auth=false), and ensure the API server is not reachable from the public internet at all - restrict it to a private network or VPN.

### `EXPOSURE_LIVE_SECRET_DETECTED`

**Live-looking secret found in exposed file** — 🔴 CRITICAL

The contents of an already-exposed file (.env, .git/config, or AWS credentials) contain one or more strings matching known live-credential formats (AWS access keys, private key blocks, Slack/GitHub/Stripe tokens, credential-embedded URLs, or other generic high-entropy secret assignments) - confirming the exposed file carries working-looking secrets, not just configuration structure.

**Remediation:** Rotate every credential found in the exposed file immediately, then remove the file from the public web root (or restrict access to it) - rotation matters even after removal, since the file may already be cached or scraped.

### `EXPOSURE_MONGO_EXPRESS_UNAUTH`

**Mongo Express exposed without authentication** — 🔴 CRITICAL

A Mongo Express web console is publicly reachable without authentication, allowing full read/write access to the underlying MongoDB data.

**Remediation:** Enable Mongo Express basic auth (ME_CONFIG_BASICAUTH), or restrict network access to the console.

### `EXPOSURE_RABBITMQ_DEFAULT_CREDS`

**RabbitMQ management API accepts default credentials** — 🔴 CRITICAL

The RabbitMQ management API on its default port (15672) accepted the well-known default credential pair (guest:guest), confirmed via a successful authenticated request. This grants full management access - viewing and manipulating queues, exchanges, and messages - to anyone who tries the default login.

**Remediation:** Change the guest user's password immediately, or delete the guest account and create named administrative accounts instead. Restrict the management port to trusted networks.

### `EXPOSURE_REDIS_UNAUTH`

**Redis exposed without authentication** — 🔴 CRITICAL

A Redis instance answered an INFO command without requiring authentication, allowing full read/write access to all stored data and, in some configurations, remote code execution via module loading.

**Remediation:** Require authentication (requirepass / ACLs) on Redis and restrict network access to trusted hosts only.

### `EXPOSURE_SOLR_ADMIN_UNAUTH`

**Apache Solr admin API exposed without authentication** — 🔴 CRITICAL

The Apache Solr admin API is reachable on its default port (8983) without authentication. Solr has no built-in authentication enabled by default, and its history includes multiple RCE-class CVEs reachable once any admin API access is available (e.g. CVE-2017-12629 XXE+RCE via the Config API, CVE-2019-0193 RCE via the DataImportHandler) - bare unauthenticated admin access is itself the meaningful finding, independent of any one specific CVE.

**Remediation:** Enable Solr's Basic Authentication or Kerberos plugin, or restrict network access to the admin port to trusted hosts only. Upgrade to a current Solr release to close any version-specific RCE vectors.

### `EXPOSURE_SPRING_BOOT_H2_CONSOLE`

**H2 database console exposed** — 🔴 CRITICAL

The H2 embedded database's web console is publicly reachable, allowing arbitrary SQL execution and, via H2's own JDBC ALIAS mechanism, remote code execution.

**Remediation:** Disable the H2 console in production (spring.h2.console.enabled=false), or restrict it to internal/authenticated access only.

### `EXPOSURE_SQL_DUMP_FILE`

**Exposed SQL database dump** — 🔴 CRITICAL

A publicly readable SQL dump file was found at a commonly-guessed path, directly disclosing database contents.

**Remediation:** Remove the dump file immediately, audit what it contained, and rotate any credentials or tokens it may have exposed.

### `EXPOSURE_SSH_PRIVATE_KEY`

**Exposed private key file** — 🔴 CRITICAL

A publicly readable PEM-format private key (RSA/DSA/EC/OpenSSH) was found at a commonly-guessed path, potentially allowing SSH access or TLS impersonation.

**Remediation:** Remove the key file from the publicly served directory immediately and revoke/rotate it - treat it as compromised.

### `EXPOSURE_SVN_ENTRIES`

**Exposed .svn/entries** — 🔴 CRITICAL

A Subversion working copy's .svn/entries file is publicly readable, disclosing the full repository URL and revision metadata and often enabling source reconstruction, the same risk EXPOSURE_GIT_CONFIG covers for Git.

**Remediation:** Remove the .svn directory from the publicly served web root, or explicitly block access to paths starting with .svn at the web server or reverse proxy.

### `EXPOSURE_VNC_NO_AUTH`

**VNC reachable with no authentication required** — 🔴 CRITICAL

A VNC server on its default port (5900) offers only the "None" security type, confirmed via the RFB protocol's own handshake, meaning any connection is granted full remote desktop access with no password or other authentication at all.

**Remediation:** Configure a VNC password immediately (or disable the "None" security type in the server's configuration), and restrict network access to the VNC port to trusted hosts only.

### `TECH_KNOWN_EXPLOITED_VULNERABILITY`

**Actively exploited vulnerability in detected software** — 🔴 CRITICAL

The fingerprinted technology and version running on this host has at least one CVE listed in CISA's Known Exploited Vulnerabilities (KEV) catalog, meaning it is confirmed to be under active exploitation in the wild - not just theoretically vulnerable.

**Remediation:** Patch or upgrade the affected software immediately. KEV entries carry CISA-recommended remediation deadlines for federal agencies and represent the highest-confidence exploitation signal available from public data.

### `EXPOSURE_ACTUATOR_BEANS`

**Spring Boot Actuator beans endpoint exposed** — 🟠 HIGH

The /actuator/beans endpoint is publicly reachable, disclosing the full internal Spring application context and architecture.

**Remediation:** Disable or authenticate the beans actuator endpoint.

### `EXPOSURE_ACTUATOR_CONFIGPROPS`

**Spring Boot Actuator configprops endpoint exposed** — 🟠 HIGH

The /actuator/configprops endpoint is publicly reachable and can disclose bound configuration properties, sometimes including secrets.

**Remediation:** Disable or authenticate the configprops actuator endpoint.

### `EXPOSURE_ACTUATOR_INDEX`

**Spring Boot Actuator index exposed** — 🟠 HIGH

The base /actuator endpoint is publicly reachable and lists available management sub-endpoints.

**Remediation:** Disable actuator on the public port, or restrict it to an internal management port with authentication.

### `EXPOSURE_ACTUATOR_LOGGERS`

**Spring Boot Actuator loggers endpoint exposed** — 🟠 HIGH

The /actuator/loggers endpoint is publicly reachable; in some configurations it also allows remotely changing log levels at runtime.

**Remediation:** Disable or authenticate the loggers actuator endpoint.

### `EXPOSURE_ACTUATOR_MAPPINGS`

**Spring Boot Actuator mappings endpoint exposed** — 🟠 HIGH

The /actuator/mappings endpoint is publicly reachable, disclosing every request mapping in the application, including undocumented or internal-only endpoints.

**Remediation:** Disable or authenticate the mappings actuator endpoint.

### `EXPOSURE_ACTUATOR_THREADDUMP`

**Spring Boot Actuator thread dump endpoint exposed** — 🟠 HIGH

The /actuator/threaddump endpoint is publicly reachable, disclosing JVM thread state and stack traces useful for reconnaissance.

**Remediation:** Disable or authenticate the threaddump actuator endpoint.

### `EXPOSURE_ADMINER`

**Adminer database console exposed** — 🟠 HIGH

An Adminer database-administration login console is publicly reachable.

**Remediation:** Remove Adminer from the publicly served path, or restrict it to an internal network/VPN with strong credentials.

### `EXPOSURE_ASPNET_ELMAH`

**ASP.NET ELMAH error log exposed** — 🟠 HIGH

The ELMAH error-logging endpoint is publicly reachable, disclosing application exception history - often including stack traces and request details.

**Remediation:** Restrict access to the ELMAH endpoint via authentication/authorization handlers, or disable the remote handler.

### `EXPOSURE_ASPNET_TRACE_AXD`

**ASP.NET trace.axd exposed** — 🟠 HIGH

ASP.NET's trace.axd diagnostic page is publicly reachable, disclosing recent request details including headers, session state, and server variables.

**Remediation:** Set trace enabled="false" in web.config, or restrict trace.axd to localOnly.

### `EXPOSURE_CONSUL_UNAUTH`

**Consul API exposed without authentication** — 🟠 HIGH

The Consul HTTP API is reachable without authentication, disclosing service topology and potentially secrets stored in the KV store.

**Remediation:** Enable Consul ACLs and restrict network access to the API.

### `EXPOSURE_GRAFANA_UNAUTH`

**Grafana exposed without authentication** — 🟠 HIGH

A Grafana instance's API is reachable without authentication, disclosing dashboard configuration and potentially connected data-source details.

**Remediation:** Enable Grafana authentication and disable anonymous access (auth.anonymous.enabled=false).

### `EXPOSURE_GRAPHQL_INTROSPECTION`

**GraphQL introspection enabled** — 🟠 HIGH

The GraphQL endpoint accepts introspection queries without authentication, disclosing the full schema and often hinting at unexposed administrative operations.

**Remediation:** Disable introspection in production, or require authentication before it is permitted.

### `EXPOSURE_KIBANA_UNAUTH`

**Kibana console exposed without authentication** — 🟠 HIGH

A Kibana dashboard is publicly reachable without authentication, exposing indexed data and potentially the underlying Elasticsearch cluster.

**Remediation:** Place Kibana behind authentication (e.g. a reverse proxy with SSO, or Elastic's built-in security features) and restrict network access.

### `EXPOSURE_LARAVEL_DEBUG_MODE`

**Laravel debug mode enabled** — 🟠 HIGH

Laravel's APP_DEBUG is enabled in production, causing unhandled errors to render a full stack trace - including file paths, code context, and sometimes environment variables - to any visitor who triggers one.

**Remediation:** Set APP_DEBUG=false in the production environment configuration.

### `EXPOSURE_LARAVEL_TELESCOPE`

**Laravel Telescope exposed** — 🟠 HIGH

Laravel's Telescope debugging dashboard is publicly reachable, disclosing application requests, queries, queued jobs, and exceptions - often including request parameters and session/cookie data.

**Remediation:** Restrict Telescope's gate to authorized users only, or disable it in production.

### `EXPOSURE_MLFLOW_UNAUTH`

**MLflow tracking server exposed without authentication** — 🟠 HIGH

An MLflow tracking server's API on its default port (5000) is reachable, disclosing every experiment, run, metric, parameter, and model artifact path tracked on the server. MLflow has no built-in authentication mechanism at all, so reachability itself is the finding.

**Remediation:** Put an authenticating reverse proxy in front of the MLflow tracking server, or restrict access to trusted internal networks only.

### `EXPOSURE_PGADMIN`

**pgAdmin console exposed** — 🟠 HIGH

A pgAdmin database-administration login console is publicly reachable.

**Remediation:** Restrict network access to the pgAdmin console to trusted hosts only, and ensure a strong master password is set.

### `EXPOSURE_PHPMYADMIN`

**phpMyAdmin console exposed** — 🟠 HIGH

A phpMyAdmin login console is publicly reachable, giving attackers a direct interface to attempt database compromise.

**Remediation:** Restrict phpMyAdmin to an internal network or VPN, and ensure strong unique credentials are enforced.

### `EXPOSURE_PHP_INFO`

**phpinfo() page exposed** — 🟠 HIGH

A publicly reachable phpinfo() page discloses detailed server configuration - loaded extensions, filesystem paths, and sometimes environment variables containing secrets.

**Remediation:** Remove the phpinfo() page from production, or restrict it to authenticated/internal access only.

### `EXPOSURE_PROMETHEUS_SERVER_UNAUTH`

**Prometheus server exposed without authentication** — 🟠 HIGH

The Prometheus server's own query API is reachable on its default port (9090) without authentication, disclosing the full scrape configuration - every monitored service/job name across the whole fleet. This is distinct from, and broader than, a single application's own exposed /metrics endpoint.

**Remediation:** Put an authenticating reverse proxy in front of the Prometheus server, or restrict access to trusted internal networks only. Prometheus has no built-in authentication of its own.

### `EXPOSURE_SNMP_DEFAULT_COMMUNITY`

**SNMP accepts the default "public" community string** — 🟠 HIGH

An SNMP agent answered a GetRequest for sysDescr.0 using the well-known default community string "public", confirmed via a real GetResponse reply. This discloses device and network configuration details and, depending on the agent's configuration, may also allow write access (SNMP SET) using the same or another commonly-guessed community string.

**Remediation:** Change the default community strings immediately, restrict SNMP access to trusted management hosts only (via ACLs on the device), and migrate to SNMPv3 with authentication/encryption where supported.

### `EXPOSURE_TRAEFIK_DASHBOARD_UNAUTH`

**Traefik dashboard exposed without authentication** — 🟠 HIGH

The Traefik reverse-proxy dashboard/API is reachable without authentication, disclosing internal backend routing and service topology.

**Remediation:** Disable the insecure API/dashboard, or place it behind authentication middleware and restrict network access.

### `EXPOSURE_ACTUATOR_HEALTH_DETAILS`

**Spring Boot Actuator health endpoint discloses internal system details** — 🟡 MEDIUM

The /actuator/health endpoint returns a detailed component breakdown (e.g. absolute filesystem paths, disk free/total capacity, database or SSL/certificate component state) to an unauthenticated caller, rather than just the overall status. Spring Boot's default for this is to show no component detail publicly, so this requires an explicit show-details=always setting or an authorization check that isn't actually being enforced - and it discloses real internal infrastructure detail useful for reconnaissance, not just "a health check exists".

**Remediation:** Set management.endpoint.health.show-details to "never" (or "when-authorized" with authorization genuinely enforced) so unauthenticated callers see only the overall status.

### `EXPOSURE_APACHE_SERVER_STATUS`

**Apache mod_status page exposed** — 🟡 MEDIUM

The Apache mod_status page (/server-status) is publicly reachable, disclosing currently in-flight requests - including client IP addresses and the URLs/query strings being processed, which can themselves carry session tokens or other sensitive parameters.

**Remediation:** Restrict /server-status to trusted internal IPs only (Apache's Require/Allow directives), or disable mod_status entirely if not needed.

### `EXPOSURE_DIRECTORY_LISTING`

**Directory listing enabled** — 🟡 MEDIUM

A web server directory listing (Apache/nginx autoindex) is publicly reachable on a commonly exposed path, disclosing the names of every file it contains - including backups, logs, or uploads that were never meant to be individually discoverable.

**Remediation:** Disable directory autoindexing for this path (Apache: "Options -Indexes"; nginx: "autoindex off;", the default) and add an index file or explicit access control if the directory must remain reachable.

### `EXPOSURE_DOCUMENT_METADATA_PATH_LEAK`

**Internal file path disclosed in document metadata** — 🟡 MEDIUM

A publicly reachable document (PDF or Office file) linked from the site's homepage contains, in its embedded metadata, what looks like an internal filesystem path - a local username's home directory or a network share - typically left behind by the authoring application rather than anything visible when the document is opened normally.

**Remediation:** Strip metadata from documents before publishing them (most Office applications and PDF tools have a built-in "remove personal information"/"sanitize" feature), and avoid saving authored documents under paths that reveal internal usernames or network share names.

### `EXPOSURE_DS_STORE`

**Exposed .DS_Store file** — 🟡 MEDIUM

A macOS Finder .DS_Store file is publicly readable, disclosing the names of files and subfolders Finder has seen in this directory - including ones no longer present in the live listing - useful for reconnaissance of the site's real directory structure.

**Remediation:** Remove the .DS_Store file from the deployed site and add it to .gitignore/deployment exclusions so it is never re-uploaded; configure the web server to deny access to dotfiles as a defense-in-depth measure.

### `EXPOSURE_JS_SOURCE_MAP`

**JavaScript source map exposed** — 🟡 MEDIUM

A publicly readable source map for one of this page's own JS bundles was found, disclosing the original, unminified source code - including any comments, internal file/folder structure, and business logic the build process would otherwise have stripped out.

**Remediation:** Exclude .map files from the production build output, or restrict them to internal access only.

### `EXPOSURE_NGINX_STUB_STATUS`

**nginx stub_status page exposed** — 🟡 MEDIUM

The nginx stub_status module is publicly reachable, disclosing aggregate connection and request counts for this server - internal infrastructure load/capacity information useful for targeting denial-of-service attacks.

**Remediation:** Restrict the stub_status location to trusted internal IPs only (nginx's allow/deny directives), or disable the module entirely if not needed.

### `EXPOSURE_PROMETHEUS_METRICS`

**Prometheus metrics endpoint exposed** — 🟡 MEDIUM

An unauthenticated /metrics endpoint in Prometheus's text exposition format is publicly reachable, disclosing internal service names, request counts, and other operational telemetry useful for reconnaissance.

**Remediation:** Restrict /metrics to internal network access or require authentication (e.g. a reverse-proxy auth layer).

### `EXPOSURE_SWAGGER_UI`

**Unauthenticated API schema exposed** — 🟡 MEDIUM

A Swagger/OpenAPI schema document is publicly reachable without authentication, disclosing the full API surface including any internal or administrative endpoints it describes.

**Remediation:** Require authentication for API documentation endpoints in non-development environments, or disable them entirely in production.

### `EXPOSURE_WORDPRESS_USER_ENUMERATION`

**WordPress user enumeration via REST API** — 🟡 MEDIUM

WordPress's REST API users endpoint (/wp-json/wp/v2/users) publicly lists every registered account's slug - often the real login username - and display name. This directly feeds credential-stuffing and brute-force attacks by telling an attacker exactly which usernames to target.

**Remediation:** Restrict the REST API users endpoint to authenticated requests only (via a security plugin such as Wordfence, or a small must-use plugin filtering the rest_endpoints hook), and avoid author slugs that match real login usernames.

### `EXPOSURE_WORDPRESS_XMLRPC`

**WordPress xmlrpc.php enabled** — 🟡 MEDIUM

WordPress's xmlrpc.php endpoint is enabled and reachable. Its system.multicall method lets an attacker attempt thousands of login guesses in a single HTTP request, bypassing simple per-request rate limiting, and its pingback.ping method can be abused as a server-side request forgery vector to make the site itself probe arbitrary internal or external URLs.

**Remediation:** Disable xmlrpc.php entirely if the site does not use the WordPress mobile app or Jetpack (which rely on it), via a security plugin or by blocking the path at the web server/reverse proxy.

### `TECH_EOL_SOFTWARE_DETECTED`

**End-of-life software detected** — 🟡 MEDIUM

The fingerprinted release cycle of a detected technology has reached end-of-life and receives no further security patches from its vendor, even for vulnerabilities not yet discovered - a forward-looking risk distinct from any specific known CVE.

**Remediation:** Upgrade to a still-maintained release cycle of this software as soon as practical.

### `TECH_KNOWN_CVE`

**Known CVE in detected software version** — 🟡 MEDIUM

The fingerprinted technology and version running on this host has one or more published CVEs in the National Vulnerability Database. Reported severity is derived from the highest CVSS base score found among them.

**Remediation:** Review the referenced CVE(s) and apply the vendor-recommended patch or upgrade. Not every listed CVE is necessarily exploitable in your specific configuration - use this as a prioritization signal alongside other findings, not a certainty.

### `TECH_EOL_APPROACHING`

**Software approaching end-of-life** — 🔵 LOW

The fingerprinted release cycle of a detected technology is scheduled to reach end-of-life within the next 90 days - an advance heads-up to plan an upgrade before it actually stops receiving patches.

**Remediation:** Plan and schedule an upgrade to a newer release cycle before its end-of-life date.

### `EXPOSURE_ACTUATOR_HEALTH`

**Spring Boot Actuator health endpoint exposed** — ⚪ INFO

The /actuator/health endpoint is publicly reachable. This is commonly intentional (used by load balancers/orchestrators for health checks) and is reported for visibility only.

**Remediation:** No action needed if intentional; otherwise disable or authenticate the health actuator endpoint.

### `EXPOSURE_ACTUATOR_INFO`

**Spring Boot Actuator info endpoint exposed** — ⚪ INFO

The /actuator/info endpoint is publicly reachable. This is commonly intentional (build/version banners) and is reported for visibility only.

**Remediation:** No action needed if intentional; otherwise disable or authenticate the info actuator endpoint.

### `EXPOSURE_DOCUMENT_METADATA_AUTHOR_INFO`

**Author/editor information disclosed in document metadata** — ⚪ INFO

A publicly reachable document's embedded metadata discloses author, editor, or authoring-application information - individually low-risk, but useful for an attacker enumerating real employee names or internal usernames.

**Remediation:** Strip metadata from documents before publishing them if author/editor names should not be public.

### `EXPOSURE_SECURITY_TXT_EXPIRED`

**security.txt has expired** — ⚪ INFO

The published /.well-known/security.txt file's Expires field is in the past, indicating the disclosure policy may be stale or no longer actively maintained.

**Remediation:** Update the Expires field to a current future date after confirming the contact details are still accurate.

### `EXPOSURE_SECURITY_TXT_PRESENT`

**security.txt published** — ⚪ INFO

A /.well-known/security.txt file was found, indicating the organization publishes a vulnerability-disclosure contact - a positive security-maturity signal, not a vulnerability.

**Remediation:** No action needed; keep the contact and expiry fields in security.txt current.

## Network / Ports

| Rule ID | Severity | Title | Scope |
|---|---|---|---|
| `NETWORK_ANONYMOUS_FTP` | 🔴 CRITICAL | Anonymous FTP login allowed | Tier 2 (deep scan) only |
| `NETWORK_IP_KNOWN_BOTNET_C2` | 🔴 CRITICAL | Target IP currently listed as active botnet C2 infrastructure | Tier 1 + Tier 2 |
| `NETWORK_MEMCACHED_EXPOSED` | 🔴 CRITICAL | Memcached reachable from the internet | Tier 1 + Tier 2 |
| `NETWORK_SMB_NETBIOS_EXPOSED` | 🔴 CRITICAL | Windows file-sharing/RPC service reachable from the internet | Tier 1 + Tier 2 |
| `NETWORK_SSH_WEAK_ALGORITHM_SUPPORTED` | 🟠 HIGH | SSH server offers a deprecated/weak algorithm | Tier 1 + Tier 2 |
| `PORT_UNEXPECTED_OPEN_ADMIN_SERVICE` | 🟠 HIGH | Administrative/database service reachable from the internet | Tier 1 + Tier 2 |
| `NETWORK_CLEARTEXT_MAIL_PROTOCOL_EXPOSED` | 🟡 MEDIUM | Cleartext mail retrieval protocol reachable | Tier 1 + Tier 2 |
| `NETWORK_DNS_OPEN_RESOLVER` | 🟡 MEDIUM | DNS server is an open recursive resolver | Tier 1 + Tier 2 |
| `PORT_OPEN_UNENCRYPTED_MGMT` | 🟡 MEDIUM | Unencrypted management protocol reachable | Tier 1 + Tier 2 |
| `NETWORK_FULL_PORT_SURFACE` | ⚪ INFO | Full-range port scan summary | Tier 2 (deep scan) only |
| `NETWORK_PROMISCUOUS_PORT_RESPONSE` | ⚪ INFO | Unusually many admin/database ports appear open at once | Tier 1 + Tier 2 |

### `NETWORK_ANONYMOUS_FTP`

**Anonymous FTP login allowed** — 🔴 CRITICAL

The FTP service on this host accepts anonymous logins, potentially exposing file listings, uploads, or sensitive data to anyone without credentials.

**Remediation:** Disable anonymous FTP access, or replace FTP with an authenticated, encrypted transfer protocol such as SFTP.

### `NETWORK_IP_KNOWN_BOTNET_C2`

**Target IP currently listed as active botnet C2 infrastructure** — 🔴 CRITICAL

An IP address currently resolving for this target is listed by abuse.ch's Feodo Tracker as an actively responding ("online") command-and-control server for a tracked banking-trojan/botnet malware family. This can mean this host's own infrastructure has been compromised and is running malware C2 software - but cloud IP addresses are also frequently reassigned between unrelated tenants, so a shared-hosting/cloud IP previously used by the botnet operator and since reassigned to this target is a real, non-malicious possibility worth ruling out first.

**Remediation:** Investigate the host at this IP immediately for signs of compromise (unexpected processes, outbound connections, unfamiliar scheduled tasks). If the host is confirmed clean, check whether the IP is on dynamically-assigned cloud infrastructure that may simply have been reused since the malware operator's own use of it ended.

### `NETWORK_MEMCACHED_EXPOSED`

**Memcached reachable from the internet** — 🔴 CRITICAL

Memcached's default port (11211) was found open and reachable from the internet. Memcached ships with no authentication at all by default, so a reachable instance discloses whatever an application cached in it - often including session tokens and query results - to anyone who connects. Internet-exposed memcached servers were also the vector behind the largest DDoS amplification attacks on record, since its UDP protocol variant has no source-address validation and an amplification factor that can exceed 50,000x.

**Remediation:** Bind memcached to localhost or a private network interface only, and firewall port 11211 (both TCP and UDP) from the internet. If UDP support is not required, disable it explicitly (-U 0).

### `NETWORK_SMB_NETBIOS_EXPOSED`

**Windows file-sharing/RPC service reachable from the internet** — 🔴 CRITICAL

A port used by SMB, NetBIOS, or the Windows RPC endpoint mapper (445/139/135) was found open and reachable from the internet. These protocols were never designed for internet exposure and have a long history of wormable, pre-authentication remote code execution vulnerabilities (e.g. MS17-010/EternalBlue, exploited by WannaCry and NotPetya) - internet-facing SMB is one of the most consistently dangerous network exposures a host can have.

**Remediation:** Block inbound access to ports 445/139/135 at the perimeter firewall. These protocols should never be reachable from the public internet - restrict them to the internal network only, behind a VPN if remote access is genuinely needed.

### `NETWORK_SSH_WEAK_ALGORITHM_SUPPORTED`

**SSH server offers a deprecated/weak algorithm** — 🟠 HIGH

The deep scan's SSH handshake probe found this server is willing to negotiate at least one deprecated or cryptographically weak key-exchange, host-key, cipher, or MAC algorithm - a client that still offers it (an outdated SSH client, or one deliberately downgraded by an attacker) can still use it, regardless of what a modern client would normally pick.

**Remediation:** Remove the weak algorithm(s) from the server's SSH daemon configuration (e.g. OpenSSH's KexAlgorithms/HostKeyAlgorithms/Ciphers/MACs directives in sshd_config) - current OpenSSH defaults already exclude everything this check flags.

### `PORT_UNEXPECTED_OPEN_ADMIN_SERVICE`

**Administrative/database service reachable from the internet** — 🟠 HIGH

A port commonly used by a database or remote-administration service (e.g. RDP, MySQL, PostgreSQL, MongoDB, Redis, MSSQL, Oracle, VNC, CouchDB, Elasticsearch, Kafka) was found open and reachable.

**Remediation:** Firewall this port to trusted networks only (e.g. a VPN or bastion), or bind the service to a private interface.

### `NETWORK_CLEARTEXT_MAIL_PROTOCOL_EXPOSED`

**Cleartext mail retrieval protocol reachable** — 🟡 MEDIUM

A port used by POP3 or IMAP's cleartext variant (110/143) was found open and reachable. Unlike their TLS-wrapped counterparts (995/993), these protocols send credentials and mail content unencrypted unless a client separately negotiates STARTTLS after connecting.

**Remediation:** Disable the cleartext port entirely if clients can use the TLS-wrapped port instead (995/993), or enforce STARTTLS and reject unencrypted authentication on the cleartext port.

### `NETWORK_DNS_OPEN_RESOLVER`

**DNS server is an open recursive resolver** — 🟡 MEDIUM

This nameserver answers recursive DNS queries for domains it has no authority over, from any client on the internet, not just this organization's own infrastructure. Open resolvers are a classic DNS-amplification DDoS reflector (RFC 5358): an attacker spoofing a victim's source IP can use this server to send the victim amplified, unwanted traffic.

**Remediation:** Disable recursion for clients outside this organization's own network (e.g. BIND's "allow-recursion", or the equivalent on your DNS server software), or restrict the server to answering only as authoritative for its own zones.

### `PORT_OPEN_UNENCRYPTED_MGMT`

**Unencrypted management protocol reachable** — 🟡 MEDIUM

A port used by a plaintext management protocol (FTP or Telnet) was found open, allowing credentials and traffic to be intercepted in transit.

**Remediation:** Disable the plaintext service and replace it with an encrypted equivalent (SFTP/FTPS instead of FTP, SSH instead of Telnet).

### `NETWORK_FULL_PORT_SURFACE`

**Full-range port scan summary** — ⚪ INFO

A full 65535-port scan (beyond the Tier 1 curated common-port list) was completed against this host, giving a complete picture of its internet-reachable TCP surface.

**Remediation:** Review the reported open-port count against what is expected for this host and close anything not intentionally exposed.

### `NETWORK_PROMISCUOUS_PORT_RESPONSE`

**Unusually many admin/database ports appear open at once** — ⚪ INFO

Several commonly-flagged administrative/database ports (covering multiple unrelated vendor protocols) all appear open on this host simultaneously - a pattern real infrastructure essentially never produces, and much more consistent with a firewall, load balancer, or WAF accepting TCP connections on every port than with that many distinct services genuinely being exposed.

**Remediation:** Verify directly whether any of the listed ports are actually running the service they are conventionally associated with before treating this as confirmed exposure - a bare TCP accept with no protocol response behind it is not the same as a reachable database or admin service.

## DNS Posture

| Rule ID | Severity | Title | Scope |
|---|---|---|---|
| `DNS_ZONE_TRANSFER_ALLOWED` | 🔴 CRITICAL | DNS zone transfer (AXFR) allowed | Tier 1 + Tier 2 |
| `DNS_DMARC_MISSING` | 🟠 HIGH | Missing DMARC record | Tier 1 + Tier 2 |
| `DNS_MX_TO_DANGLING_HOST` | 🟠 HIGH | MX record points to a non-resolving host | Tier 1 + Tier 2 |
| `DNS_SPF_INCLUDE_DANGLING` | 🟠 HIGH | SPF record includes a domain with no SPF record of its own | Tier 1 + Tier 2 |
| `DNS_SPF_LOOKUP_LIMIT_EXCEEDED` | 🟠 HIGH | SPF record exceeds the 10-lookup limit | Tier 1 + Tier 2 |
| `DNS_SPF_MISSING` | 🟠 HIGH | Missing SPF record | Tier 1 + Tier 2 |
| `DNS_SPF_MULTIPLE_RECORDS` | 🟠 HIGH | Multiple SPF records published | Tier 1 + Tier 2 |
| `DNSSEC_NOT_ENABLED` | 🟡 MEDIUM | DNSSEC not enabled | Tier 1 + Tier 2 |
| `DNS_DKIM_WEAK_KEY` | 🟡 MEDIUM | DKIM record uses a weak RSA key | Tier 1 + Tier 2 |
| `DNS_DMARC_POLICY_NONE` | 🟡 MEDIUM | DMARC policy set to none | Tier 1 + Tier 2 |
| `DNS_DMARC_SUBDOMAIN_POLICY_WEAKER` | 🟡 MEDIUM | DMARC subdomain policy weaker than the domain's own policy | Tier 1 + Tier 2 |
| `DNS_NS_LAME_DELEGATION` | 🟡 MEDIUM | Lame NS delegation | Tier 1 + Tier 2 |
| `DNS_SPF_MISSING_ALL_MECHANISM` | 🟡 MEDIUM | SPF record has no terminating all mechanism | Tier 1 + Tier 2 |
| `DNS_SPF_TOO_PERMISSIVE` | 🟡 MEDIUM | Overly permissive SPF record | Tier 1 + Tier 2 |
| `EMAIL_MTA_STS_MISSING` | 🟡 MEDIUM | MTA-STS not fully enforced | Tier 1 + Tier 2 |
| `DNS_CAA_MISSING` | 🔵 LOW | Missing CAA record | Tier 1 + Tier 2 |
| `DNS_DKIM_NOT_DETECTED` | 🔵 LOW | No DKIM record found at common selector names | Tier 1 + Tier 2 |
| `DNS_SOA_RETRY_EXCEEDS_REFRESH` | 🔵 LOW | SOA retry interval is not shorter than the refresh interval | Tier 1 + Tier 2 |
| `DNS_SOA_SERIAL_STALE` | 🔵 LOW | SOA serial suggests an unmaintained zone | Tier 1 + Tier 2 |
| `DNS_SPF_PTR_MECHANISM_DEPRECATED` | 🔵 LOW | SPF record uses the deprecated ptr mechanism | Tier 1 + Tier 2 |
| `EMAIL_DMARC_PCT_BELOW_100` | 🔵 LOW | DMARC policy applies to only a fraction of mail | Tier 1 + Tier 2 |
| `EMAIL_DMARC_RUA_MISSING` | 🔵 LOW | DMARC record has no aggregate report address | Tier 1 + Tier 2 |
| `EMAIL_TLS_RPT_MISSING` | 🔵 LOW | TLS-RPT not configured | Tier 1 + Tier 2 |
| `EMAIL_BIMI_ABSENT` | ⚪ INFO | No BIMI record published | Tier 1 + Tier 2 |

### `DNS_ZONE_TRANSFER_ALLOWED`

**DNS zone transfer (AXFR) allowed** — 🔴 CRITICAL

This nameserver answered an unauthenticated zone transfer request, disclosing the domain's complete DNS zone - every subdomain, internal hostname, and record it holds - in a single query.

**Remediation:** Disable unauthenticated zone transfers (AXFR) on this nameserver, restricting them to specific, authenticated secondary servers only.

### `DNS_DMARC_MISSING`

**Missing DMARC record** — 🟠 HIGH

No DMARC record was found at _dmarc.<domain>, so spoofed mail claiming to be from this domain is not policed.

**Remediation:** Publish a DMARC TXT record at _dmarc.<domain> starting with v=DMARC1.

### `DNS_MX_TO_DANGLING_HOST`

**MX record points to a non-resolving host** — 🟠 HIGH

This domain's MX record points to a mail server hostname that no longer resolves (no A or AAAA record) - the same takeover shape as a dangling CNAME, applied to mail routing: anyone able to register or re-point that abandoned hostname could intercept mail addressed to this domain.

**Remediation:** Remove the stale MX record, or re-point it at a mail server you actually control.

### `DNS_SPF_INCLUDE_DANGLING`

**SPF record includes a domain with no SPF record of its own** — 🟠 HIGH

This domain's SPF record references another domain via include: that has no SPF TXT record of its own - the same takeover shape as a dangling CNAME or MX, applied to SPF: whoever can register or reconfigure that referenced domain could add themselves as an authorized sender for this domain's mail.

**Remediation:** Remove the stale include:, or ensure the referenced domain has a valid SPF record you control.

### `DNS_SPF_LOOKUP_LIMIT_EXCEEDED`

**SPF record exceeds the 10-lookup limit** — 🟠 HIGH

This domain's SPF record requires more than 10 DNS "lookup" mechanisms (include/a/mx/ptr/exists/redirect) once every nested include is followed - RFC 7208 mandates a hard PermError past this limit, meaning most mail servers checking SPF for this domain treat it as if SPF were entirely broken, regardless of how carefully the policy itself was written.

**Remediation:** Reduce the number of include: mechanisms (flatten rarely-changing third-party includes into direct ip4/ip6 ranges where the provider publishes them, or drop providers no longer in use) until the total lookup count is at or under 10.

### `DNS_SPF_MISSING`

**Missing SPF record** — 🟠 HIGH

No Sender Policy Framework record was found, allowing any server to send email appearing to originate from this domain.

**Remediation:** Publish an SPF TXT record listing authorized sending servers.

### `DNS_SPF_MULTIPLE_RECORDS`

**Multiple SPF records published** — 🟠 HIGH

More than one SPF-type TXT record was found at this domain's apex. Per RFC 7208, this makes SPF evaluation return PermError regardless of what either record says - mail servers checking SPF for this domain get a hard failure, not the weaker of the two policies.

**Remediation:** Merge all SPF mechanisms into a single TXT record at the domain apex.

### `DNSSEC_NOT_ENABLED`

**DNSSEC not enabled** — 🟡 MEDIUM

No DNSKEY records were found for this zone, indicating the zone is not signed with DNSSEC.

**Remediation:** Enable DNSSEC signing with your DNS provider/registrar.

### `DNS_DKIM_WEAK_KEY`

**DKIM record uses a weak RSA key** — 🟡 MEDIUM

A DKIM TXT record was found with an RSA public key below 2048 bits - the current minimum recommended by DKIM deployment guidance (M3AAWG, dkim.org), matching the same line NIST drew for RSA generally in 2013. A key this size is within reach of realistic factoring resources, letting an attacker forge DKIM-valid mail from this domain.

**Remediation:** Rotate the DKIM key pair to a 2048-bit (or larger) RSA key, or migrate to an ed25519 key (RFC 8463), and publish the new public key at the same selector.

### `DNS_DMARC_POLICY_NONE`

**DMARC policy set to none** — 🟡 MEDIUM

A DMARC record exists but its policy is p=none, meaning failing messages are only monitored, not rejected or quarantined.

**Remediation:** Move the DMARC policy to p=quarantine or p=reject once monitoring confirms legitimate senders pass alignment.

### `DNS_DMARC_SUBDOMAIN_POLICY_WEAKER`

**DMARC subdomain policy weaker than the domain's own policy** — 🟡 MEDIUM

This DMARC record's sp= (subdomain policy) tag is explicitly set weaker than its own p= policy (e.g. p=reject but sp=none), carving out a lower enforcement bar for every subdomain. Spoofed mail appearing to come from any subdomain gets less protection than mail from the apex domain itself.

**Remediation:** Remove the sp= tag entirely (so p= applies uniformly to subdomains too), or set it to match or exceed the strength of p=, unless subdomains are confirmed never to send mail and a lower bar is genuinely intentional.

### `DNS_NS_LAME_DELEGATION`

**Lame NS delegation** — 🟡 MEDIUM

This nameserver is listed as authoritative for the domain but did not answer authoritatively for its zone, indicating a stale or misconfigured delegation.

**Remediation:** Remove the non-authoritative nameserver from the domain's NS records, or fix its zone configuration so it answers authoritatively.

### `DNS_SPF_MISSING_ALL_MECHANISM`

**SPF record has no terminating all mechanism** — 🟡 MEDIUM

This SPF record has no all mechanism (and no redirect= taking its place), so RFC 7208 evaluates any sender IP matching none of the earlier mechanisms as Neutral - the same practical effect as an explicit ?all, just reached by omission rather than intent. Mail from an unauthorized server gets no SPF signal against it at all.

**Remediation:** Add a terminating all mechanism (-all to hard-fail unauthorized senders, or ~all to soft-fail) at the end of the record.

### `DNS_SPF_TOO_PERMISSIVE`

**Overly permissive SPF record** — 🟡 MEDIUM

The SPF record ends in +all or ?all, which allows any server (or fails open) to send mail as this domain.

**Remediation:** Change the SPF qualifier to ~all (softfail) or -all (hardfail) once all legitimate senders are enumerated.

### `EMAIL_MTA_STS_MISSING`

**MTA-STS not fully enforced** — 🟡 MEDIUM

Either the _mta-sts DNS TXT record or the https://mta-sts.<domain>/.well-known/mta-sts.txt policy file is missing, so inbound mail servers have no way to enforce TLS when delivering mail to this domain.

**Remediation:** Publish both the _mta-sts TXT record and a valid MTA-STS policy file to require TLS for inbound mail delivery.

### `DNS_CAA_MISSING`

**Missing CAA record** — 🔵 LOW

No CAA record restricts which Certificate Authorities may issue certificates for this domain.

**Remediation:** Publish a CAA record naming your authorized CA(s) to reduce the risk of mis-issued certificates.

### `DNS_DKIM_NOT_DETECTED`

**No DKIM record found at common selector names** — 🔵 LOW

No DKIM TXT record was found at any commonly-used selector name (default, google, selector1, selector2, k1, dkim). DKIM selector names are arbitrary, so this is a best-effort check - a real DKIM setup using an uncommon selector would not be detected by this probe.

**Remediation:** Confirm DKIM signing is configured for this domain's outbound mail; if it already is under a non-standard selector, no action is needed.

### `DNS_SOA_RETRY_EXCEEDS_REFRESH`

**SOA retry interval is not shorter than the refresh interval** — 🔵 LOW

RFC 1912 2.2 says the SOA retry value (how often a secondary nameserver re-attempts a failed zone refresh) should be smaller than the refresh value (the normal successful re-check interval). Here retry is equal to or larger than refresh, so a secondary that misses one refresh gets no extra chances before the next regularly scheduled one anyway - a secondary can drift stale for longer than intended after a transient outage on the primary nameserver.

**Remediation:** Set the zone's SOA retry value below its refresh value (common values: refresh 86400, retry 7200).

### `DNS_SOA_SERIAL_STALE`

**SOA serial suggests an unmaintained zone** — 🔵 LOW

This zone's SOA serial number, read under the common YYYYMMDDnn convention, encodes a date more than 2 years in the past - a signal (not proof, since not every zone uses this convention) that the zone's DNS records haven't been updated in a long time and may reflect abandoned or unmaintained infrastructure.

**Remediation:** Confirm the zone is still actively managed; if it is, no action is needed beyond noting the serial convention isn't being kept current.

### `DNS_SPF_PTR_MECHANISM_DEPRECATED`

**SPF record uses the deprecated ptr mechanism** — 🔵 LOW

This domain's SPF record uses the ptr (or ptr:domain) mechanism, which RFC 7208 5.5 explicitly says SHOULD NOT be used: it requires a slow reverse-then-forward DNS lookup per sender IP, is unreliable, and some mail validators skip evaluating it entirely or treat its mere presence as an automatic SPF failure.

**Remediation:** Replace the ptr mechanism with explicit ip4:/ip6:/include: mechanisms naming the actual sending infrastructure.

### `EMAIL_DMARC_PCT_BELOW_100`

**DMARC policy applies to only a fraction of mail** — 🔵 LOW

The DMARC record's pct= value is below 100, so its policy (quarantine/reject) is only enforced for a sampled percentage of messages that fail authentication - the rest are treated as if the policy were p=none, regardless of how strict the policy itself looks.

**Remediation:** Raise pct= to 100 once you're confident the policy isn't generating false positives.

### `EMAIL_DMARC_RUA_MISSING`

**DMARC record has no aggregate report address** — 🔵 LOW

A DMARC record exists but has no rua= tag, so nobody receives aggregate reports of authentication failures - even a strict p=reject policy is running with no visibility into what's actually being blocked or who's sending unauthenticated mail as this domain.

**Remediation:** Add a rua= tag to the DMARC record pointing at a mailbox or report-processing service you control.

### `EMAIL_TLS_RPT_MISSING`

**TLS-RPT not configured** — 🔵 LOW

No _smtp._tls TXT record was found, so this domain receives no reports when other mail servers fail to negotiate TLS while delivering mail to it.

**Remediation:** Publish a TLS-RPT TXT record pointing at an address or endpoint that should receive TLS delivery failure reports.

### `EMAIL_BIMI_ABSENT`

**No BIMI record published** — ⚪ INFO

No default._bimi TXT record was found. BIMI lets supporting mail clients display a verified brand logo next to authenticated mail from this domain - its absence is a maturity signal, not a vulnerability.

**Remediation:** Consider publishing a BIMI record (requires DMARC enforcement and, for most providers, a Verified Mark Certificate) to improve brand visibility in supporting mail clients.

## TLS / HSTS

| Rule ID | Severity | Title | Scope |
|---|---|---|---|
| `TLS_CERT_EXPIRED` | 🔴 CRITICAL | TLS certificate expired | Tier 1 + Tier 2 |
| `TLS_POODLE_VULNERABLE` | 🔴 CRITICAL | Vulnerable to POODLE (CVE-2014-3566) | Tier 1 + Tier 2 |
| `TLS_CERT_HOSTNAME_MISMATCH` | 🟠 HIGH | TLS certificate does not match hostname | Tier 1 + Tier 2 |
| `TLS_CERT_KEY_TOO_SHORT` | 🟠 HIGH | Certificate public key too short | Tier 1 + Tier 2 |
| `TLS_CERT_SELF_SIGNED_OR_UNTRUSTED_CHAIN` | 🟠 HIGH | Untrusted or self-signed TLS certificate chain | Tier 1 + Tier 2 |
| `TLS_CERT_SIGNATURE_ALGORITHM_WEAK` | 🟠 HIGH | Certificate signed with a weak signature algorithm | Tier 1 + Tier 2 |
| `TLS_WEAK_PROTOCOL_SUPPORTED` | 🟠 HIGH | Legacy TLS protocol supported | Tier 1 + Tier 2 |
| `TLS_CERT_EXPIRING_SOON` | 🟡 MEDIUM | TLS certificate expiring soon | Tier 1 + Tier 2 |
| `TLS_CT_UNEXPECTED_ISSUER` | 🟡 MEDIUM | Certificate issued by an unrecognized CA | Tier 1 + Tier 2 |
| `TLS_NO_FORWARD_SECRECY` | 🟡 MEDIUM | No forward secrecy | Tier 1 + Tier 2 |
| `TLS_NO_HSTS` | 🟡 MEDIUM | Missing HSTS header | Tier 1 + Tier 2 |
| `TLS_WEAK_CIPHER_SUITE` | 🟡 MEDIUM | Weak TLS cipher suite negotiated | Tier 1 + Tier 2 |
| `TLS_1_3_NOT_SUPPORTED` | 🔵 LOW | TLS 1.3 not supported | Tier 1 + Tier 2 |
| `TLS_HSTS_NOT_ON_PRELOAD_LIST` | 🔵 LOW | HSTS preload token present but domain is not on the real preload list | Tier 1 + Tier 2 |
| `TLS_HSTS_PRELOAD_NOT_ELIGIBLE` | 🔵 LOW | HSTS preload token present without meeting preload requirements | Tier 1 + Tier 2 |
| `TLS_HSTS_SHORT_MAX_AGE` | 🔵 LOW | Weak HSTS policy | Tier 1 + Tier 2 |

### `TLS_CERT_EXPIRED`

**TLS certificate expired** — 🔴 CRITICAL

The certificate presented for this host has already expired, so browsers and clients will reject or warn on every connection.

**Remediation:** Renew and deploy a new certificate immediately.

### `TLS_POODLE_VULNERABLE`

**Vulnerable to POODLE (CVE-2014-3566)** — 🔴 CRITICAL

This server still accepts SSLv3, whose CBC-mode cipher suites have a padding design flaw with no fix short of disabling the protocol entirely - an attacker able to intercept and manipulate traffic (e.g. on a shared network) can use repeated padding-oracle requests to decrypt small amounts of plaintext, such as session cookies, one byte at a time.

**Remediation:** Disable SSLv3 entirely in the server's TLS configuration - there is no patch for POODLE short of this.

### `TLS_CERT_HOSTNAME_MISMATCH`

**TLS certificate does not match hostname** — 🟠 HIGH

The certificate presented for this host is not valid for its name - none of its Subject Alternative Names cover it. Every browser and API client will refuse the connection (or users will be trained to click through warnings); the host is typically serving another site's certificate through a shared load balancer or a copy-pasted config.

**Remediation:** Issue a certificate that includes this hostname in its Subject Alternative Names (or a wildcard for its parent), or stop serving this name from an endpoint whose certificate does not cover it.

### `TLS_CERT_KEY_TOO_SHORT`

**Certificate public key too short** — 🟠 HIGH

The certificate's RSA/DSA public key is under 2048 bits, below the minimum modern CAs and browsers require - a key this size is within range of being factored, undermining every guarantee the certificate is meant to provide.

**Remediation:** Re-issue the certificate with at least a 2048-bit RSA key (or migrate to a modern EC key).

### `TLS_CERT_SELF_SIGNED_OR_UNTRUSTED_CHAIN`

**Untrusted or self-signed TLS certificate chain** — 🟠 HIGH

The certificate chain presented for this host does not validate against a public trust root.

**Remediation:** Deploy a certificate issued by a publicly trusted Certificate Authority.

### `TLS_CERT_SIGNATURE_ALGORITHM_WEAK`

**Certificate signed with a weak signature algorithm** — 🟠 HIGH

The certificate is signed using MD5 or SHA-1, both of which are cryptographically broken for signature purposes and are no longer trusted by modern browsers - a forged certificate with a colliding signature is feasible for an attacker with sufficient resources.

**Remediation:** Re-issue the certificate from a CA using a modern signature algorithm (SHA-256 or stronger).

### `TLS_WEAK_PROTOCOL_SUPPORTED`

**Legacy TLS protocol supported** — 🟠 HIGH

The server accepted a handshake using a deprecated TLS protocol version (TLSv1 or TLSv1.1), both retired by major browsers and PCI-DSS.

**Remediation:** Disable TLSv1 and TLSv1.1 on the server, allowing only TLSv1.2 and TLSv1.3.

### `TLS_CERT_EXPIRING_SOON`

**TLS certificate expiring soon** — 🟡 MEDIUM

The certificate presented for this host expires within 30 days.

**Remediation:** Renew the certificate before expiry; consider automated renewal (e.g. ACME/Let's Encrypt) to prevent recurrence.

### `TLS_CT_UNEXPECTED_ISSUER`

**Certificate issued by an unrecognized CA** — 🟡 MEDIUM

The presented certificate was issued by a Certificate Authority outside a curated list of major, well-known public CAs. This can be entirely legitimate, but is also a pattern seen with MITM interception, phishing infrastructure impersonating this domain, or a misconfigured/compromised issuance pipeline.

**Remediation:** Confirm the issuing CA is expected and authorized; if not, investigate how the certificate was issued and consider revoking it.

### `TLS_NO_FORWARD_SECRECY`

**No forward secrecy** — 🟡 MEDIUM

The negotiated cipher suite does not use an ephemeral (ECDHE/DHE) key exchange, meaning this connection's session key is derived from the server's long-term private key rather than a fresh per-session one. If that private key is ever compromised, every past session recorded by an eavesdropper (not just future ones) can be decrypted retroactively - the exact property forward secrecy exists to prevent.

**Remediation:** Prefer/require ECDHE (or DHE) cipher suites in the server's TLS configuration, and disable plain RSA-key-exchange suites.

### `TLS_NO_HSTS`

**Missing HSTS header** — 🟡 MEDIUM

The response has no Strict-Transport-Security header, so browsers will not enforce HTTPS-only connections for this host.

**Remediation:** Add a Strict-Transport-Security header with a long max-age and includeSubDomains.

### `TLS_WEAK_CIPHER_SUITE`

**Weak TLS cipher suite negotiated** — 🟡 MEDIUM

The server negotiated a cipher suite using a known-weak algorithm (e.g. RC4, DES/3DES, NULL, EXPORT, or MD5).

**Remediation:** Reconfigure the server's cipher suite preference list to exclude weak/legacy ciphers.

### `TLS_1_3_NOT_SUPPORTED`

**TLS 1.3 not supported** — 🔵 LOW

This host does not negotiate TLS 1.3, the current protocol version. Qualys SSL Labs caps its grade at A- for a server missing it - every supported connection is still using an older protocol generation, with weaker default cipher/handshake choices and strictly more historical attack surface than 1.3 was designed to remove.

**Remediation:** Enable TLS 1.3 support in the server's TLS configuration - most modern web servers and load balancers support it with a configuration change alone.

### `TLS_HSTS_NOT_ON_PRELOAD_LIST`

**HSTS preload token present but domain is not on the real preload list** — 🔵 LOW

The Strict-Transport-Security header includes the preload token, but hstspreload.org's own status API confirms this domain is not actually included in the list browsers ship (it may never have been submitted, or may have since been removed). Unlike TLS_HSTS_PRELOAD_NOT_ELIGIBLE (which checks whether the header's own values meet the submission bar), this checks the real-world outcome: browsers give this site no preload protection regardless of how the header reads.

**Remediation:** Submit the domain at hstspreload.org once the policy meets its eligibility bar, or remove the preload token from the header if it is not actually intended to be submitted.

### `TLS_HSTS_PRELOAD_NOT_ELIGIBLE`

**HSTS preload token present without meeting preload requirements** — 🔵 LOW

The Strict-Transport-Security header includes the preload token, but hstspreload.org (the source of every browser's built-in preload list) requires max-age of at least 1 year and includeSubDomains before it will accept a submission. The token gives a false sense of protection: browsers ignore it entirely unless the site is actually on the list, and it won't be while the underlying policy is this weak.

**Remediation:** Either raise max-age to at least 31536000 (1 year) and add includeSubDomains to actually qualify, or remove the preload token until the policy meets hstspreload.org's submission requirements.

### `TLS_HSTS_SHORT_MAX_AGE`

**Weak HSTS policy** — 🔵 LOW

A Strict-Transport-Security header is present but its max-age is under 6 months and/or it is missing includeSubDomains.

**Remediation:** Set max-age to at least 15552000 (6 months, ideally 31536000/1 year) and include includeSubDomains.

## HTTP Headers

| Rule ID | Severity | Title | Scope |
|---|---|---|---|
| `CORS_CREDENTIALED_ORIGIN_REFLECTION` | 🟠 HIGH | CORS reflects arbitrary Origin with credentials allowed | Tier 1 + Tier 2 |
| `COOKIE_MISSING_HTTPONLY_FLAG` | 🟡 MEDIUM | Cookie missing HttpOnly flag | Tier 1 + Tier 2 |
| `COOKIE_MISSING_SECURE_FLAG` | 🟡 MEDIUM | Cookie missing Secure flag | Tier 1 + Tier 2 |
| `HEADER_CSP_MISSING` | 🟡 MEDIUM | Missing Content-Security-Policy header | Tier 1 + Tier 2 |
| `HEADER_CSP_WEAK_POLICY` | 🟡 MEDIUM | Content-Security-Policy allows unsafe or unrestricted script execution | Tier 1 + Tier 2 |
| `HEADER_REFERRER_POLICY_UNSAFE` | 🟡 MEDIUM | Referrer-Policy set to unsafe-url | Tier 1 + Tier 2 |
| `HTTP_NO_HTTPS_REDIRECT` | 🟡 MEDIUM | Plain HTTP not redirected to HTTPS | Tier 1 + Tier 2 |
| `HTTP_TRACE_METHOD_ENABLED` | 🟡 MEDIUM | HTTP TRACE method enabled | Tier 1 + Tier 2 |
| `COOKIE_DOMAIN_TOO_BROAD` | 🔵 LOW | Cookie scoped to a parent domain, not just this host | Tier 1 + Tier 2 |
| `COOKIE_MISSING_SAMESITE` | 🔵 LOW | Cookie missing SameSite attribute | Tier 1 + Tier 2 |
| `HEADER_XCTO_INVALID_VALUE` | 🔵 LOW | X-Content-Type-Options set to an invalid value | Tier 1 + Tier 2 |
| `HEADER_XCTO_MISSING` | 🔵 LOW | Missing X-Content-Type-Options header | Tier 1 + Tier 2 |
| `HEADER_XFO_MISSING` | 🔵 LOW | Missing X-Frame-Options header | Tier 1 + Tier 2 |
| `COOKIE_MISSING_HOST_PREFIX` | ⚪ INFO | Cookie not using __Host-/__Secure- name prefix | Tier 1 + Tier 2 |
| `HEADER_COOP_MISSING` | ⚪ INFO | Missing Cross-Origin-Opener-Policy header | Tier 1 + Tier 2 |
| `HEADER_CORP_MISSING` | ⚪ INFO | Missing Cross-Origin-Resource-Policy header | Tier 1 + Tier 2 |
| `HEADER_PERMISSIONS_POLICY_MISSING` | ⚪ INFO | Missing Permissions-Policy header | Tier 1 + Tier 2 |
| `HEADER_REFERRER_POLICY_MISSING` | ⚪ INFO | Missing Referrer-Policy header | Tier 1 + Tier 2 |
| `HEADER_SERVER_BANNER_VERBOSE` | ⚪ INFO | Verbose server banner | Tier 1 + Tier 2 |

### `CORS_CREDENTIALED_ORIGIN_REFLECTION`

**CORS reflects arbitrary Origin with credentials allowed** — 🟠 HIGH

The server echoes back whatever Origin header it receives in Access-Control-Allow-Origin while also sending Access-Control-Allow-Credentials: true, rather than checking the Origin against a real allowlist. Any malicious website can exploit this to make authenticated cross-origin requests using a logged-in victim's own cookies and read the response.

**Remediation:** Validate the Origin header against an explicit allowlist of known-good origins before echoing it back, and only ever set Access-Control-Allow-Credentials: true for origins on that allowlist - never reflect an arbitrary Origin verbatim.

### `COOKIE_MISSING_HTTPONLY_FLAG`

**Cookie missing HttpOnly flag** — 🟡 MEDIUM

A cookie was set without the HttpOnly flag, making it readable by client-side JavaScript and easier to steal via XSS.

**Remediation:** Set the HttpOnly attribute on cookies that do not need JavaScript access.

### `COOKIE_MISSING_SECURE_FLAG`

**Cookie missing Secure flag** — 🟡 MEDIUM

A cookie was set without the Secure flag, allowing it to be transmitted over unencrypted HTTP.

**Remediation:** Set the Secure attribute on all cookies.

### `HEADER_CSP_MISSING`

**Missing Content-Security-Policy header** — 🟡 MEDIUM

The response has no Content-Security-Policy header, reducing protection against XSS and data-injection attacks.

**Remediation:** Define and roll out a Content-Security-Policy header appropriate to the application.

### `HEADER_CSP_WEAK_POLICY`

**Content-Security-Policy allows unsafe or unrestricted script execution** — 🟡 MEDIUM

A Content-Security-Policy header is present, but its script-src/default-src directive allows 'unsafe-inline', 'unsafe-eval', or a bare wildcard (*) source - each of which defeats most of CSP's real protection against injected-script attacks. A policy with 'unsafe-inline' lets an attacker-injected inline <script> run exactly as if no policy were set at all.

**Remediation:** Remove 'unsafe-inline'/'unsafe-eval' from script-src/default-src (use nonces or hashes for legitimate inline scripts instead) and replace a bare wildcard source with an explicit allowlist of trusted origins.

### `HEADER_REFERRER_POLICY_UNSAFE`

**Referrer-Policy set to unsafe-url** — 🟡 MEDIUM

A Referrer-Policy header is present, but its value is (or falls back to) unsafe-url - the worst possible setting. It sends the complete referrer URL, including the full path and query string (which routinely carries session tokens, API keys, or other sensitive data), on every navigation: cross-origin requests and even HTTPS-to-HTTP downgrades, where every other policy value withholds at least the path.

**Remediation:** Replace unsafe-url with a safer policy such as strict-origin-when-cross-origin (the current browser default) or no-referrer.

### `HTTP_NO_HTTPS_REDIRECT`

**Plain HTTP not redirected to HTTPS** — 🟡 MEDIUM

The site answers on cleartext HTTP without redirecting to HTTPS. Anything a user or client sends before reaching the HTTPS version - and every visit that starts from an http:// link or a typed hostname - is readable and modifiable by anyone on the network path.

**Remediation:** Answer every plain-HTTP request with a 301 to the same path on https://, as the first hop, then enable HSTS (and preload) so browsers stop making the cleartext request at all.

### `HTTP_TRACE_METHOD_ENABLED`

**HTTP TRACE method enabled** — 🟡 MEDIUM

The server processes HTTP TRACE requests instead of rejecting them (405/501), echoing the request back as the response body. This enables Cross-Site Tracing (XST): combined with a cross-site scripting or CSRF primitive elsewhere on the site, TRACE lets an attacker's script read back a cookie's value even when that cookie is marked HttpOnly, by echoing the request headers that carried it.

**Remediation:** Disable the TRACE (and TRACK, on IIS) HTTP method at the web server or reverse proxy level. On Apache, add "TraceEnable off"; on nginx, block the method explicitly (nginx has no native TRACE support, but a proxied/upstream backend can still echo it); on IIS, remove TRACE/TRACK via a URL Rewrite rule or the RequestFiltering verb denylist.

### `COOKIE_DOMAIN_TOO_BROAD`

**Cookie scoped to a parent domain, not just this host** — 🔵 LOW

A cookie sets its Domain attribute to a parent of the host that set it, broadening the cookie's scope to every subdomain rather than just this one (the default, safer behavior when Domain is left out entirely). The cookie is sent to - and, without HttpOnly, readable by script running on - any one of those subdomains, including one that has since been abandoned or taken over.

**Remediation:** Remove the Domain attribute entirely (the cookie will then default to host-only scope), or set it to the exact host rather than a parent domain, unless the cookie genuinely needs to be shared across subdomains.

### `COOKIE_MISSING_SAMESITE`

**Cookie missing SameSite attribute** — 🔵 LOW

A cookie was set without a SameSite attribute, offering no baseline CSRF protection from the browser.

**Remediation:** Set SameSite=Lax or SameSite=Strict on cookies where cross-site sending is not required.

### `HEADER_XCTO_INVALID_VALUE`

**X-Content-Type-Options set to an invalid value** — 🔵 LOW

The X-Content-Type-Options header is present, but its value isn't nosniff - the only value browsers recognize. Any other value is silently ignored, leaving the response just as open to MIME-sniffing as if the header were missing entirely.

**Remediation:** Set the header to exactly "X-Content-Type-Options: nosniff".

### `HEADER_XCTO_MISSING`

**Missing X-Content-Type-Options header** — 🔵 LOW

The response has no X-Content-Type-Options: nosniff header, allowing browsers to MIME-sniff responses.

**Remediation:** Add X-Content-Type-Options: nosniff.

### `HEADER_XFO_MISSING`

**Missing X-Frame-Options header** — 🔵 LOW

The response has no X-Frame-Options header, leaving the site potentially vulnerable to clickjacking.

**Remediation:** Add X-Frame-Options: DENY or SAMEORIGIN (or an equivalent frame-ancestors CSP directive).

### `COOKIE_MISSING_HOST_PREFIX`

**Cookie not using __Host-/__Secure- name prefix** — ⚪ INFO

A cookie sets the Secure flag but its name doesn't use the __Host- or __Secure- prefix. These prefixes get the browser itself to enforce the cookie's security properties (__Host- additionally blocks it from being overwritten by a subdomain or a non-root path) rather than relying solely on attributes a misconfiguration could drop.

**Remediation:** Rename security-sensitive cookies to use the __Host- prefix (or __Secure- if a non-root path/Domain attribute is required).

### `HEADER_COOP_MISSING`

**Missing Cross-Origin-Opener-Policy header** — ⚪ INFO

The response has no Cross-Origin-Opener-Policy header, leaving the page's window open to being referenced by cross-origin popups/tabs it opens - a prerequisite for several browser side-channel attacks (e.g. Spectre-style cross-origin data leaks).

**Remediation:** Add a Cross-Origin-Opener-Policy: same-origin header.

### `HEADER_CORP_MISSING`

**Missing Cross-Origin-Resource-Policy header** — ⚪ INFO

The response has no Cross-Origin-Resource-Policy header, so this resource can be loaded cross-origin (e.g. embedded via <script>/<img>) by any other site without an explicit opt-out.

**Remediation:** Add a Cross-Origin-Resource-Policy header (same-origin or same-site) to responses that don't need to be cross-origin embeddable.

### `HEADER_PERMISSIONS_POLICY_MISSING`

**Missing Permissions-Policy header** — ⚪ INFO

The response has no Permissions-Policy header restricting browser feature access (camera, geolocation, etc.).

**Remediation:** Add a Permissions-Policy header scoped to the features the application actually needs.

### `HEADER_REFERRER_POLICY_MISSING`

**Missing Referrer-Policy header** — ⚪ INFO

The response has no Referrer-Policy header, so the browser default (often full referrer leakage) applies.

**Remediation:** Add a Referrer-Policy header, e.g. strict-origin-when-cross-origin.

### `HEADER_SERVER_BANNER_VERBOSE`

**Verbose server banner** — ⚪ INFO

The Server or X-Powered-By header discloses specific software/version information useful for targeting known vulnerabilities.

**Remediation:** Suppress or generalize the Server/X-Powered-By headers at the web server or proxy layer.

## Subdomain Hygiene

| Rule ID | Severity | Title | Scope |
|---|---|---|---|
| `SUBDOMAIN_DANGLING_CNAME` | 🔴 CRITICAL | Dangling CNAME - possible subdomain takeover | Tier 1 + Tier 2 |
| `SUBDOMAIN_NS_DELEGATION_TAKEOVER` | 🔴 CRITICAL | Dangling NS delegation - possible subdomain takeover | Tier 1 + Tier 2 |
| `SUBDOMAIN_STALE_NOT_RESOLVING` | 🔵 LOW | Subdomain no longer resolving | Tier 1 + Tier 2 |
| `SUBDOMAIN_NEW_UNEXPECTED` | ⚪ INFO | New subdomain discovered | Tier 1 + Tier 2 |
| `SUBDOMAIN_WILDCARD_DNS` | ⚪ INFO | Wildcard DNS detected | Tier 1 + Tier 2 |

### `SUBDOMAIN_DANGLING_CNAME`

**Dangling CNAME - possible subdomain takeover** — 🔴 CRITICAL

This subdomain has a CNAME record pointing to a third-party service (e.g. S3, GitHub Pages, Heroku, Azure, Zendesk, Shopify, or Fastly) resource that appears to be unclaimed. An attacker who registers the same resource name on that service can serve arbitrary content from this subdomain.

**Remediation:** Either remove the stale CNAME record if the resource is no longer needed, or immediately re-claim the corresponding resource on the third-party service to prevent takeover.

### `SUBDOMAIN_NS_DELEGATION_TAKEOVER`

**Dangling NS delegation - possible subdomain takeover** — 🔴 CRITICAL

This subdomain is delegated (via NS records) to a cloud DNS provider's nameservers, but no hosted zone answers authoritatively for it there - the delegation appears to point at a deprovisioned or never-created zone. Anyone who notices can create a matching zone at that provider and become fully authoritative for this subdomain, including mail (MX) and any other record type - not just a single HTTP response like a dangling CNAME.

**Remediation:** Remove the dangling NS delegation from this domain's DNS if the zone is no longer needed, or immediately recreate the hosted zone at the provider to reclaim it.

### `SUBDOMAIN_STALE_NOT_RESOLVING`

**Subdomain no longer resolving** — 🔵 LOW

This subdomain was previously discovered and tracked but no longer resolves to any IP address, which may indicate abandoned infrastructure or a dangling DNS record.

**Remediation:** Remove the stale DNS record if the subdomain is genuinely decommissioned, or investigate why it stopped resolving if it should still be live.

### `SUBDOMAIN_NEW_UNEXPECTED`

**New subdomain discovered** — ⚪ INFO

A subdomain not previously observed for this target was discovered via certificate-transparency-based enumeration.

**Remediation:** Confirm this subdomain is expected and intentionally exposed; decommission it if it is not.

### `SUBDOMAIN_WILDCARD_DNS`

**Wildcard DNS detected** — ⚪ INFO

This zone resolves arbitrary, non-existent subdomains, which means passive subdomain enumeration results for this target may include false positives and should be interpreted with that in mind.

**Remediation:** No action required; this is contextual information about how to interpret this target's subdomain inventory, not a vulnerability.

## Brand / Typosquat

| Rule ID | Severity | Title | Scope |
|---|---|---|---|
| `BRAND_TYPOSQUAT_HOSTING_LIVE_SITE` | 🔴 CRITICAL | Lookalike domain is hosting a live website | Tier 1 + Tier 2 |
| `BRAND_TYPOSQUAT_MX_CONFIGURED` | 🔴 CRITICAL | Lookalike domain has mail servers configured | Tier 1 + Tier 2 |
| `TYPOSQUAT_DOMAIN_REGISTERED` | 🟠 HIGH | Registered lookalike domain detected | Tier 1 + Tier 2 |
| `BRAND_IMPERSONATING_APP_DETECTED` | 🟡 MEDIUM | Possible brand-impersonating app found on an app store | Tier 1 + Tier 2 |

### `BRAND_TYPOSQUAT_HOSTING_LIVE_SITE`

**Lookalike domain is hosting a live website** — 🔴 CRITICAL

A registered lookalike domain is serving a live, renderable web page rather than just holding a DNS record, consistent with active phishing/impersonation content.

**Remediation:** Pursue takedown/UDRP action for the lookalike domain and its hosting provider; consider a phishing-content report to browser safe-browsing lists.

### `BRAND_TYPOSQUAT_MX_CONFIGURED`

**Lookalike domain has mail servers configured** — 🔴 CRITICAL

A registered lookalike domain has MX records configured - it isn't just parked, it's set up to receive email, consistent with active phishing-reply capture or business-email-compromise staging.

**Remediation:** Pursue takedown/UDRP action for the lookalike domain, and warn staff/customers this pattern is associated with active phishing infrastructure, not just a coincidental registration.

### `TYPOSQUAT_DOMAIN_REGISTERED`

**Registered lookalike domain detected** — 🟠 HIGH

A domain closely resembling this target's own - generated via common typosquatting techniques (character omission/duplication/transposition, keyboard-adjacent substitution, ASCII homoglyph substitution, cross-script IDN/Unicode homograph substitution, TLD swap, or hyphenation) - is registered and actively resolving. This is consistent with phishing or brand-impersonation infrastructure, though it can occasionally be a coincidentally similarly-named, unrelated legitimate site.

**Remediation:** Investigate the flagged domain to confirm whether it is malicious. If so, consider reporting it to the registrar/host, pursuing a UDRP proceeding, or blocking it at your organization's email/web gateways.

### `BRAND_IMPERSONATING_APP_DETECTED`

**Possible brand-impersonating app found on an app store** — 🟡 MEDIUM

An app on the Apple App Store or Google Play mentions this organization's brand name in its title, but is published under a developer name that doesn't itself contain the brand - unlike this organization's own real app listings. This can be a legitimate unofficial fan app or review tool, but is also a pattern seen with fake banking/finance apps designed to phish credentials or card details.

**Remediation:** Review the app listing directly. If it is impersonating your brand or app, report it to the relevant app store's abuse/trademark-infringement reporting process for takedown.

## WHOIS / Domain

| Rule ID | Severity | Title | Scope |
|---|---|---|---|
| `WHOIS_DOMAIN_PENDING_DELETE` | 🔴 CRITICAL | Domain registration has lapsed and is pending deletion | Tier 1 + Tier 2 |
| `WHOIS_EXPIRY_APPROACHING` | 🟠 HIGH | Domain registration expiring soon | Tier 1 + Tier 2 |
| `WHOIS_NO_TRANSFER_LOCK` | 🟡 MEDIUM | Domain has no transfer lock | Tier 1 + Tier 2 |
| `WHOIS_REGISTRANT_CHANGED` | ⚪ INFO | Domain registrar changed | Tier 1 + Tier 2 |

### `WHOIS_DOMAIN_PENDING_DELETE`

**Domain registration has lapsed and is pending deletion** — 🔴 CRITICAL

This domain's WHOIS/RDAP status shows pendingDelete or redemptionPeriod, meaning the registration has already expired and the domain is in ICANN's deletion pipeline. Once released it can be registered by anyone, who could then hijack residual trust, inbound email, or traffic still pointed at this domain.

**Remediation:** Contact the registrar immediately to redeem the domain (a redemption fee applies during redemptionPeriod; pendingDelete is no longer redeemable and the domain will be released to the public).

### `WHOIS_EXPIRY_APPROACHING`

**Domain registration expiring soon** — 🟠 HIGH

This domain's registration expires within 30 days. An expired domain can be re-registered by a third party, enabling phishing and full takeover of email and web traffic.

**Remediation:** Renew the domain registration and enable auto-renewal with the registrar.

### `WHOIS_NO_TRANSFER_LOCK`

**Domain has no transfer lock** — 🟡 MEDIUM

This domain's WHOIS/RDAP status shows no clientTransferProhibited (or equivalent registry) lock, making it easier for an attacker with access to the registrant account or registrar to initiate an unauthorized transfer away from the current registrar.

**Remediation:** Enable the registrar's transfer-lock (clientTransferProhibited) status for this domain.

### `WHOIS_REGISTRANT_CHANGED`

**Domain registrar changed** — ⚪ INFO

The registrar on record for this domain changed since the previous WHOIS/RDAP observation.

**Remediation:** Confirm this change was intentional (e.g. a planned registrar transfer); investigate immediately if it was not.

## Breach Data

| Rule ID | Severity | Title | Scope |
|---|---|---|---|
| `BREACH_EMAIL_DOMAIN_IN_KNOWN_BREACH` | 🟡 MEDIUM | Domain associated with a known data breach | Tier 1 + Tier 2 |

### `BREACH_EMAIL_DOMAIN_IN_KNOWN_BREACH`

**Domain associated with a known data breach** — 🟡 MEDIUM

Email addresses at this domain have appeared in a publicly known data breach, indicating credentials or personal data tied to this domain may be exposed and available to attackers.

**Remediation:** Enforce mandatory password resets for affected accounts, enable multi-factor authentication organization-wide, and monitor for credential-stuffing attempts against services using this domain.

## Compound Risk

| Rule ID | Severity | Title | Scope |
|---|---|---|---|
| `COMPOUND_ACTIVELY_EXPLOITED_EXPOSURE` | 🔴 CRITICAL | Actively-exploited software on an already-exposed host | Tier 1 + Tier 2 |
| `COMPOUND_CONTAINER_ESCAPE_AMPLIFICATION` | 🔴 CRITICAL | Exposed Docker API alongside another serious finding | Tier 1 + Tier 2 |
| `COMPOUND_CREDENTIAL_TO_DATA_PIVOT` | 🔴 CRITICAL | Exposed credentials with a reachable path to data | Tier 1 + Tier 2 |
| `COMPOUND_SOURCE_AND_CREDENTIAL_EXPOSURE` | 🔴 CRITICAL | Full source checkout exposed alongside live credentials | Tier 1 + Tier 2 |
| `COMPOUND_INTERCEPTABLE_ADMIN_ACCESS` | 🟠 HIGH | Admin console reachable over weak or untrusted transport | Tier 1 + Tier 2 |

### `COMPOUND_ACTIVELY_EXPLOITED_EXPOSURE`

**Actively-exploited software on an already-exposed host** — 🔴 CRITICAL

The fingerprinted software on this asset has a CVE confirmed by CISA's Known Exploited Vulnerabilities catalog to be under active exploitation in the wild right now - not just theoretically vulnerable. Finding that on a host that also has a separate exposure/misconfiguration finding is the highest-confidence "this will actually get hit" signal Bloodhound can produce: real attackers are actively scanning for exactly this CVE.

**Remediation:** Patch the actively-exploited software immediately - this is the single highest-priority item this platform can surface. Then address the accompanying exposure finding on the same host.

### `COMPOUND_CONTAINER_ESCAPE_AMPLIFICATION`

**Exposed Docker API alongside another serious finding** — 🔴 CRITICAL

An unauthenticated Docker Engine API is already close to full host compromise on its own (it can create, run, and mount volumes into containers). A second Critical or High finding on the same asset means whatever that finding exposes - credentials, another service, a misconfiguration - can very plausibly be reached or escalated from inside a container the Docker API lets an attacker spin up.

**Remediation:** Restrict the Docker API to localhost/a private network immediately and require TLS client-certificate authentication for any remote access. Then remediate the second contributing finding, since it is now reachable via a much wider blast radius than it would be alone.

### `COMPOUND_CREDENTIAL_TO_DATA_PIVOT`

**Exposed credentials with a reachable path to data** — 🔴 CRITICAL

This host leaks live credentials or source (an exposed .env file, AWS credentials, or a full .git checkout) AND separately exposes an unauthenticated database or admin service on the same asset. Neither finding alone hands over data - together they are close to a complete credential-to-data pivot: an attacker does not need to guess or crack anything, just read the leaked secret and connect to the open service right next to it.

**Remediation:** Remediate both contributing findings, but treat the credential exposure as the higher priority: rotate any secrets that may have been leaked immediately, then remove the exposed file/service and restrict access to the data store to only the hosts that genuinely need it.

### `COMPOUND_SOURCE_AND_CREDENTIAL_EXPOSURE`

**Full source checkout exposed alongside live credentials** — 🔴 CRITICAL

This asset exposes both a full .git checkout (enabling reconstruction of the entire source repository) and a live .env file with application secrets. Together that is close to a complete compromise kit handed directly to an attacker: the application's own code to study, plus the credentials to run it against production.

**Remediation:** Remove both exposed paths immediately and rotate every credential that appeared in the .env file - treat them as already compromised, not merely at risk.

### `COMPOUND_INTERCEPTABLE_ADMIN_ACCESS`

**Admin console reachable over weak or untrusted transport** — 🟠 HIGH

An exposed admin console (Jenkins script console, phpMyAdmin, or an unauthenticated Kibana) is bad enough on its own. On this asset it is also reachable over a connection that is not safely encrypted - a self-signed/untrusted certificate, a legacy TLS protocol still accepted, or no HSTS - meaning credentials typed into that console are at real risk of interception in transit, not just abuse once reached.

**Remediation:** Restrict access to the admin console (network-level allowlisting or authentication in front of it) and fix the TLS configuration on this host - a valid trusted certificate, modern protocol versions only, and HSTS enabled.
