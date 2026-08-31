-- Spring Authorization Server's own default JDBC schema (see V40__oauth2_authorization_server.sql)
-- ships oauth2_authorization with no index beyond its own primary key. mcp.McpConnectionRepository
-- (the admin "Connected clients" list/revoke feature) filters and sorts on
-- (registered_client_id, principal_name) on every load, which - without this - is a full table
-- scan plus an in-memory sort of the whole table every time an admin opens the MCP page.
CREATE INDEX idx_oauth2_authorization_client_principal
    ON oauth2_authorization (registered_client_id, principal_name);
