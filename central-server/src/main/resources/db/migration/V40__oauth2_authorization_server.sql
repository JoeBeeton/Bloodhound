-- Spring Authorization Server's own default JDBC schema (adapted for PostgreSQL - every 'blob'
-- column becomes 'text' and 'timestamp' becomes 'timestamptz', per this project's own convention
-- and the schema file's own documented PostgreSQL caveat), backing JdbcRegisteredClientRepository/
-- JdbcOAuth2AuthorizationService/JdbcOAuth2AuthorizationConsentService - see
-- https://github.com/spring-projects/spring-authorization-server (Apache-2.0) for the canonical
-- source. Column names/types are NOT otherwise changed from upstream: Spring's own JDBC
-- implementations use column-name-based RowMappers against this exact shape, so this schema is
-- deliberately NOT restyled to match this project's usual UUID-primary-key convention - ids stay
-- varchar, matching what Spring's own code generates and expects.
--
-- No organization_id/user_id column here - a "registered client" is an MCP client application
-- (e.g. "Claude Desktop"), not a Bloodhound org, and a single registered client can be used by
-- users across many orgs. Org-scoping happens at the token layer (a custom OAuth2TokenCustomizer
-- adds org/role claims for the authenticated principal), not in this generic OAuth2 client/
-- authorization bookkeeping - principal_name below already carries which Bloodhound user granted
-- a given authorization, which is all Spring's own AS machinery needs to know.

CREATE TABLE oauth2_registered_client (
    id varchar(100) NOT NULL,
    client_id varchar(100) NOT NULL,
    client_id_issued_at timestamptz DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret varchar(200) DEFAULT NULL,
    client_secret_expires_at timestamptz DEFAULT NULL,
    client_name varchar(200) NOT NULL,
    client_authentication_methods varchar(1000) NOT NULL,
    authorization_grant_types varchar(1000) NOT NULL,
    redirect_uris varchar(1000) DEFAULT NULL,
    post_logout_redirect_uris varchar(1000) DEFAULT NULL,
    scopes varchar(1000) NOT NULL,
    client_settings varchar(2000) NOT NULL,
    token_settings varchar(2000) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE oauth2_authorization (
    id varchar(100) NOT NULL,
    registered_client_id varchar(100) NOT NULL,
    principal_name varchar(200) NOT NULL,
    authorization_grant_type varchar(100) NOT NULL,
    authorized_scopes varchar(1000) DEFAULT NULL,
    attributes text DEFAULT NULL,
    state varchar(500) DEFAULT NULL,
    authorization_code_value text DEFAULT NULL,
    authorization_code_issued_at timestamptz DEFAULT NULL,
    authorization_code_expires_at timestamptz DEFAULT NULL,
    authorization_code_metadata text DEFAULT NULL,
    access_token_value text DEFAULT NULL,
    access_token_issued_at timestamptz DEFAULT NULL,
    access_token_expires_at timestamptz DEFAULT NULL,
    access_token_metadata text DEFAULT NULL,
    access_token_type varchar(100) DEFAULT NULL,
    access_token_scopes varchar(1000) DEFAULT NULL,
    oidc_id_token_value text DEFAULT NULL,
    oidc_id_token_issued_at timestamptz DEFAULT NULL,
    oidc_id_token_expires_at timestamptz DEFAULT NULL,
    oidc_id_token_metadata text DEFAULT NULL,
    refresh_token_value text DEFAULT NULL,
    refresh_token_issued_at timestamptz DEFAULT NULL,
    refresh_token_expires_at timestamptz DEFAULT NULL,
    refresh_token_metadata text DEFAULT NULL,
    user_code_value text DEFAULT NULL,
    user_code_issued_at timestamptz DEFAULT NULL,
    user_code_expires_at timestamptz DEFAULT NULL,
    user_code_metadata text DEFAULT NULL,
    device_code_value text DEFAULT NULL,
    device_code_issued_at timestamptz DEFAULT NULL,
    device_code_expires_at timestamptz DEFAULT NULL,
    device_code_metadata text DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE oauth2_authorization_consent (
    registered_client_id varchar(100) NOT NULL,
    principal_name varchar(200) NOT NULL,
    authorities varchar(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);
